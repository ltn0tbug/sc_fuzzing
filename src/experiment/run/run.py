"""Unified experiment runner — one CLI + one resumable driver over the
method × dataset registry.

Replaces the 10 per-(method, dataset) scripts + run_all.py + verify_one.py.
The method's entry function, hyperparameter defaults and per-method knobs come
from `registry.METHOD_SPECS`; the dataset's kind + result layout from
`registry.DATASET_SPECS`; the regime/backend defaults from `profile.py`.

Usage:
    uv run python src/experiment/run/run.py <method|all> --dataset smartbugs|defihacklabs
        [--mode test|medium|long|very_long]   # override profile.EXPERIMENT_MODE
        [--backend anthropic|claude-code|llama-cpp]   # override profile.LLM_BACKEND
        [--only <contract_id>]                # restrict to one contract
        [--verify]                            # write to output/experiment/_verify/, skip registry
        [--output-dir <path>]                 # override results ROOT (default output/experiment/);
                                              #   full run lands under <path>/<dataset>/<method>/
        [--no-skip-on-fail]                   # abort on first crash
        [--debug]

Examples:
    uv run python src/experiment/run/run.py sscfuzz --dataset smartbugs
    uv run python src/experiment/run/run.py all --dataset smartbugs --mode test
    uv run python src/experiment/run/run.py sscfuzz --dataset defihacklabs \
        --only defihacklabs/2020-12_Cover --verify

Each method×dataset cell is resumable: contracts already in
output/experiment/<dataset>/<method>/_summary.json are skipped on re-run.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
ROOT = _HERE.parents[2]                                  # src/experiment/run → repo root
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src" / "experiment" / "dataloader"))

import exp_profile  # noqa: E402  (src/experiment/run/exp_profile.py — name avoids stdlib `profile`)
from registry import (  # noqa: E402
    DATASET_SPECS,
    METHOD_ALIASES,
    METHOD_SPECS,
    DatasetSpec,
    MethodSpec,
    resolve_method,
)
from scaffold import RESULTS_ROOT, prepare, preflight_fork  # noqa: E402
from schema import Contract, load_dataset  # noqa: E402

from fuzz import checkpoint as _ckpt  # noqa: E402  (inner iteration-level resume)


# ── Config assembly ───────────────────────────────────────────────────────────

def _build_config(method: MethodSpec, ds: DatasetSpec, prepared, *,
                  mode: str, backend: str, iterations: int | None = None,
                  checkpoint_path: str | None = None, checkpoint_every: int = 0,
                  keep_checkpoint: bool = False,
                  load_model: str | None = None, save_model: str | None = None):
    kwargs = dict(mode=mode, contract_name=prepared.target, foundry_project=str(prepared.work))
    if ds.kind == "fork":
        kwargs["fork"] = prepared.fork_cfg
    cfg = method.defaults.materialize(**kwargs)
    # Thread the whole runtime `extend` bag from the dataset row into the config;
    # the method entry point (main.run_fuzzing_loop) forwards it to the FoundryFuzzer
    # + LLM client. prepare() returns None for keys a given row/kind doesn't use,
    # so this is safe for both kinds:
    #   fork   → external / setup_template (declared on-chain vars + custom template)
    #   inline → constructor_args/value, pre_deploy/setup_calls (co-located dep
    #            deploy + wiring), and optionally external/setup_template (escape hatch)
    cfg.external = prepared.external
    cfg.setup_template = prepared.setup_template
    cfg.constructor_args = prepared.ctor_args
    cfg.constructor_value = prepared.ctor_value
    cfg.pre_deploy = prepared.pre_deploy
    cfg.setup_calls = prepared.setup_calls
    # Only sscfuzz/llmfuzz materialize() accept llm_overrides; set the backend
    # post-hoc so the same path works for madfuzz too (matches its old runner).
    if method.uses_llm:
        cfg.llm.backend = backend
    if iterations is not None:        # raw override of the mode regime's budget
        cfg.max_iterations = iterations
    # Inner (iteration-level) resume: sscfuzz + baselines read these off the config
    # and flush/restore loop state every `checkpoint_every` iters. None/0 disables.
    cfg.checkpoint_path = checkpoint_path
    cfg.checkpoint_every = checkpoint_every
    cfg.keep_checkpoint = keep_checkpoint
    # Cross-contract DQN transfer (pretraining): warm-start from / persist to a .pt.
    cfg.load_model_path = load_model
    cfg.save_model_path = save_model
    return cfg


def _run_contract(method: MethodSpec, ds: DatasetSpec, contract: Contract, *,
                  mode: str, backend: str, iterations: int | None, debug: bool,
                  checkpoint_path: str | None = None, checkpoint_every: int = 0,
                  keep_checkpoint: bool = False,
                  load_model: str | None = None, save_model: str | None = None) -> tuple[dict, dict | None]:
    """Scaffold + build + fuzz one contract. Returns (status_row, run_log|None)."""
    t0 = time.time()
    prepared = prepare(contract, ds)
    if not prepared.ok:
        return {"id": contract.id, "status": prepared.status, "reason": prepared.reason}, None

    cfg = _build_config(method, ds, prepared, mode=mode, backend=backend, iterations=iterations,
                        checkpoint_path=checkpoint_path, checkpoint_every=checkpoint_every,
                        keep_checkpoint=keep_checkpoint,
                        load_model=load_model, save_model=save_model)
    extra = method.extra_kwargs(exp_profile) if method.extra_kwargs else {}
    bugs, run_log = method.entry(
        cfg, prepared.source, prepared.abi, verbose=False, debug=debug, **extra
    )

    summary = run_log.get("summary", {})
    row = {
        "id": contract.id,
        "status": "ok",
        "target": prepared.target,
        "elapsed_s": round(time.time() - t0, 1),
        "bugs": len(bugs),
        "total_reward": round(summary.get("total_reward", 0.0), 2),
        # Bytecode-level coverage (matches reward signal); source-level counts
        # remain in the full run_log.
        "bc_branches_hit":   summary.get("total_coverage_bc_branches", 0),
        "bc_branches_total": summary.get("total_bc_branches", 0),
        "bc_coverage_ratio": round(summary.get("bc_coverage_ratio", 0.0), 4),
    }
    if ds.kind == "inline":
        row["category"] = contract.category
    else:
        row["chain"] = contract.fork.chain if contract.fork else None
        # Fork: the recompiled artifact drifted from on-chain → SOURCE coverage is
        # untrustworthy (bc/function stay on-chain-anchored + valid). Flag it so EDA
        # can exclude/annotate; bc metrics above remain correct either way.
        row["coverage_unreliable"] = bool(summary.get("coverage_unreliable", False))
    return row, run_log


# ── Resumable driver ──────────────────────────────────────────────────────────

def _method_dir(ds: DatasetSpec, method: str, *, verify: bool, root: Path = RESULTS_ROOT) -> Path:
    # <root>/<dataset>/<method>/ (verify → <root>/_verify/<dataset>/<method>/).
    # `root` defaults to the canonical RESULTS_ROOT; --output-dir overrides it so a
    # full run can land off to the side without clobbering canonical results.
    if verify:
        return root / "_verify" / ds.results_subdir / method
    return root / ds.results_subdir / method


def _select_contracts(ds: DatasetSpec, only: str | None) -> list[Contract]:
    contracts = load_dataset(ds.json_key).contracts
    if ds.filter_skip:
        contracts = [c for c in contracts if not c.skip]
    if only:
        contracts = [c for c in contracts if c.id == only]
        if not contracts:
            sys.exit(f"contract id not found in {ds.json_key}: {only}")
    return contracts


def run_method(method: MethodSpec, ds: DatasetSpec, *, mode: str, backend: str,
               iterations: int | None, only: str | None, verify: bool,
               skip_on_fail: bool, debug: bool, checkpoint_every: int = 0,
               keep_checkpoint: bool = False, output_root: Path = RESULTS_ROOT,
               load_model: str | None = None, save_model: str | None = None,
               preflight: bool = True, preflight_warm: bool = True) -> None:
    contracts = _select_contracts(ds, only)

    # Pre-flight fork-infra gate (fork datasets only): probe RPC health + warm the
    # forge cache before any measured iteration. A dead required chain ABORTS the
    # run instead of emitting fork_setup_failed for every iteration. Inline
    # datasets skip it (no fork). See scaffold.preflight_fork.
    if preflight and ds.kind == "fork":
        ok, msg = preflight_fork(contracts, ds, warm=preflight_warm, debug=debug)
        if not ok:
            sys.exit(f"Pre-flight ABORT: {msg}")

    method_dir = _method_dir(ds, method.name, verify=verify, root=output_root)
    method_dir.mkdir(parents=True, exist_ok=True)

    # Verify mode bypasses the resumable registry entirely.
    summary_path = method_dir / "_summary.json"
    if verify:
        summary = {"method": method.name, "dataset": ds.name, "results": []}
        done_ids: set[str] = set()
    elif summary_path.exists():
        summary = json.loads(summary_path.read_text())
        done_ids = {r["id"] for r in summary["results"]}
    else:
        summary = {"method": method.name, "dataset": ds.name, "results": []}
        done_ids = set()

    n = len(contracts)
    label = f"{ds.name}/{method.name}"
    budget = f"iters={iterations}" if iterations is not None else f"mode={mode}"
    print(f"\n=== {label} — running {n - len(done_ids)}/{n} contracts "
          f"({budget} backend={backend if method.uses_llm else 'n/a'}) ===\n")

    # Inner-resume checkpoints are disabled in verify mode (throwaway runs).
    ck_every = 0 if verify else checkpoint_every

    for i, contract in enumerate(contracts, 1):
        cid = contract.id
        ck_path = (str(_ckpt.checkpoint_path(method_dir, contract.safe_id))
                   if ck_every > 0 else None)
        if cid in done_ids:
            # Continue an already-done contract when --keep-checkpoint left a final
            # checkpoint AND the new budget exceeds where it stopped: resume + extend
            # (e.g. 100 → 200) instead of skipping. Needs an explicit --iterations.
            _kept = _ckpt.load(ck_path) if (ck_path and keep_checkpoint) else None
            if (_kept is not None and iterations is not None
                    and iterations > _kept.get("iteration", 0)):
                print(f"[{i:3d}/{n}] {cid} ... continuing "
                      f"{_kept['iteration']} → {iterations}", flush=True)
                summary["results"] = [r for r in summary["results"] if r["id"] != cid]
            else:
                print(f"[{i:3d}/{n}] {cid} ... skipped (already done)")
                # Tidy a stale checkpoint from a prior partial run — but keep a
                # deliberately-kept one so it stays available to continue later.
                if ck_path and not keep_checkpoint:
                    _ckpt.clear(ck_path)
                continue

        # Header on its own line so the fuzzer's rich panels render cleanly below
        # it (instead of jammed onto the trailing `... `).
        print(f"[{i:3d}/{n}] {cid}", flush=True)
        try:
            row, run_log = _run_contract(
                method, ds, contract, mode=mode, backend=backend,
                iterations=iterations, debug=debug,
                checkpoint_path=ck_path, checkpoint_every=ck_every,
                keep_checkpoint=keep_checkpoint,
                load_model=load_model, save_model=save_model,
            )
        except KeyboardInterrupt:
            print("⏸  interrupted — partial summary saved")
            if not verify:
                summary_path.write_text(json.dumps(summary, indent=2))
            raise
        except Exception as e:
            tb = traceback.format_exc(limit=2).strip().splitlines()[-1]
            row = {"id": cid, "status": "run_fail",
                   "reason": f"{type(e).__name__}: {e}", "traceback_tail": tb}
            run_log = None
            if not skip_on_fail:
                summary["results"].append(row)
                if not verify:
                    summary_path.write_text(json.dumps(summary, indent=2))
                print(f"💥 FATAL ({type(e).__name__}: {e}) — aborting")
                raise

        if run_log is not None:
            (method_dir / f"{contract.safe_id}.json").write_text(json.dumps(run_log, indent=2))
        summary["results"].append(row)
        if not verify:
            summary_path.write_text(json.dumps(summary, indent=2))
        # Contract finished (ok or a non-crash fail we chose to record) — the
        # inner checkpoint is no longer needed. A crash re-raises above WITHOUT
        # reaching here, so its checkpoint survives for the next resume. With
        # --keep-checkpoint the loop has written a FINAL checkpoint at the true
        # last iteration; keep it (+ its records sidecar) so the run can be
        # continued later with a higher --iterations.
        if ck_path and not keep_checkpoint:
            _ckpt.clear(ck_path)

        if row["status"] == "ok":
            print(f"  → ✅ bugs={row['bugs']} "
                  f"bc_cov={row['bc_branches_hit']}/{row['bc_branches_total']} "
                  f"({row['bc_coverage_ratio']:.1%}) in {row['elapsed_s']}s\n")
        else:
            print(f"  → ❌ {row['status']}: {str(row.get('reason', ''))[:80]}\n")

    counts = Counter(r["status"] for r in summary["results"])
    print(f"\n=== {label} done ===")
    for status, k in counts.most_common():
        print(f"  {status}: {k}")
    print(f"Logs: {method_dir}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("method", help="method name or 'all' (sscfuzz = alias for sscfuzz_esb)",
                   choices=list(METHOD_SPECS) + list(METHOD_ALIASES) + ["all"])
    p.add_argument("--dataset", required=True, choices=list(DATASET_SPECS))
    p.add_argument("--mode", default=exp_profile.EXPERIMENT_MODE,
                   help=f"iteration regime (default: profile.EXPERIMENT_MODE={exp_profile.EXPERIMENT_MODE})")
    p.add_argument("--backend", default=exp_profile.LLM_BACKEND,
                   help=f"LLM backend (default: profile.LLM_BACKEND={exp_profile.LLM_BACKEND})")
    p.add_argument("--iterations", type=int, default=None,
                   help="raw iteration count — overrides the --mode regime's budget")
    p.add_argument("--only", default=None, help="restrict to one contract id")
    p.add_argument("--verify", action="store_true",
                   help="write to output/experiment/_verify/, bypass the resumable registry")
    p.add_argument("--output-dir", default=None,
                   help="override the results root (default: ./output/experiment/); a full "
                        "registry-driven run lands under <output-dir>/<dataset>/<method>/ instead "
                        "of the canonical tree — use it to run without clobbering canonical results")
    p.add_argument("--no-skip-on-fail", action="store_true", help="abort on first crash")
    p.add_argument("--checkpoint-every", type=int, default=exp_profile.CHECKPOINT_EVERY,
                   help=f"inner-resume flush cadence in iterations, 0=off "
                        f"(default: profile.CHECKPOINT_EVERY={exp_profile.CHECKPOINT_EVERY})")
    p.add_argument("--keep-checkpoint", action="store_true",
                   help="on clean completion keep a final checkpoint at the true last "
                        "iteration (not cleared); re-run the same contract with a higher "
                        "--iterations to continue where it stopped (e.g. 100 → 200)")
    p.add_argument("--load-model", default=None,
                   help="warm-start a net/param-bearing selector (sscfuzz_dqn DQN, or "
                        "sscfuzz_cb's LinUCB A_a/b_a) from this file if it exists; ignored by "
                        "the net-less sscfuzz_esb bandit. Cross-contract transfer.")
    p.add_argument("--save-model", default=None,
                   help="on clean completion, save the trained model (sscfuzz_dqn net or "
                        "sscfuzz_cb A_a/b_a) here for reuse. Chain --load-model+--save-model on "
                        "one path to pretrain over a contract sequence.")
    p.add_argument("--skip-preflight", action="store_true",
                   help="skip the fork-infra pre-flight gate (RPC health + cache warm-up). "
                        "Fork datasets only; inline datasets never run it.")
    p.add_argument("--skip-warmup", action="store_true",
                   help="run the pre-flight RPC health check but SKIP the forge-cache "
                        "warm-up (faster; caches warm lazily in-run). Fork datasets only.")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    if args.verify and not args.only:
        p.error("--verify requires --only <contract_id>")

    ds = DATASET_SPECS[args.dataset]
    methods = (list(METHOD_SPECS.values()) if args.method == "all"
               else [METHOD_SPECS[resolve_method(args.method)]])
    skip_on_fail = exp_profile.SKIP_ON_FAIL and not args.no_skip_on_fail
    output_root = Path(args.output_dir).expanduser().resolve() if args.output_dir else RESULTS_ROOT

    # Run the fork pre-flight gate ONCE up front (shared across methods for `all`):
    # the selected endpoints + warmed forge cache persist for the whole process.
    if not args.skip_preflight and ds.kind == "fork":
        contracts = _select_contracts(ds, args.only)
        ok, msg = preflight_fork(contracts, ds, warm=not args.skip_warmup, debug=args.debug)
        if not ok:
            sys.exit(f"Pre-flight ABORT: {msg}")

    for method in methods:
        run_method(
            method, ds,
            mode=args.mode, backend=args.backend, iterations=args.iterations,
            only=args.only, verify=args.verify, skip_on_fail=skip_on_fail, debug=args.debug,
            checkpoint_every=args.checkpoint_every, keep_checkpoint=args.keep_checkpoint,
            output_root=output_root,
            load_model=args.load_model, save_model=args.save_model,
            preflight=False,  # already run above (avoids re-warming per method)
        )


if __name__ == "__main__":
    main()
