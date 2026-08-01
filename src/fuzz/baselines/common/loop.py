"""Shared baseline fuzzing loop.

Both RLFuzz and MADFuzz follow the same outer structure:

  for iteration in range(max_iterations):
      state = encoder.encode()
      fuzz_input, action_meta = policy.select_input(state, iteration)
      result = fuzzer.run_input(fuzz_input, strategy=reward_strategy)
      reward = compute_reward(result, strategy=reward_strategy, mode="generate")
      next_state = encoder.encode()
      encoder.update(...)
      policy.update(state, action_meta, reward, next_state)
      track bugs / coverage / run records

This module owns the loop; each policy supplies `select_input` + `update` +
`token_stats` and decides for itself how to encode actions internally.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Protocol

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ... import checkpoint as _ckpt
from ...fuzzer.foundry import FoundryFuzzer
from ...fuzzer.reward import compute_reward
from ...fuzzer.state import ContractFeatures
from ...llm.agent import FuzzInput, TokenUsage
from ...llm.strategies import GENERATION_STRATEGIES
from ...report import (
    backend_labels,
    build_bug_record,
    build_fuzzing_output,
    build_run_record,
    build_run_summary,
    render_done_panel,
    render_start_panel,
    spec_for,
)
from .config import BaselineConfig
from .state import BaselineStateEncoder

logger = logging.getLogger(__name__)


class BaselinePolicy(Protocol):
    """Interface every baseline policy implements."""

    state_dim: int
    num_groups: int
    method_name: str

    def select_input(self, state, iteration: int) -> tuple[FuzzInput, dict]:
        """Return (fuzz_input, action_meta) where action_meta carries whatever
        the policy needs in `update` (e.g. group_idx, arg indices)."""

    def update(
        self,
        state,
        action_meta: dict,
        reward: float,
        next_state,
        done: bool = False,
    ) -> None:
        """Apply one learning step."""

    def token_stats(self) -> TokenUsage | None:
        """Return cumulative LLM token usage (None for methods with no LLM use)."""


def _fn_names_in_input(fuzz_input: FuzzInput) -> list[str]:
    return [
        c[0] for c in fuzz_input.calls
        if c and isinstance(c[0], str) and c[0] != "atk.setReentrantCall"
    ]


def run_baseline_loop(
    config: BaselineConfig,
    contract_source: str,
    contract_abi: list[dict],
    policy: BaselinePolicy,
    *,
    verbose: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> tuple[list[dict], dict]:
    """Run a baseline fuzzer; returns (found_bugs, full_run_log)."""
    console = console or Console()

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    fuzzer = FoundryFuzzer(
        config.foundry_project,
        config.contract_name,
        abi=contract_abi,
        initial_balance_native=config.initial_balance_native,
        contract_source=contract_source,
        fork=getattr(config, "fork", None),
        constructor_args=getattr(config, "constructor_args", None),
        constructor_value=getattr(config, "constructor_value", None),
        pre_deploy=getattr(config, "pre_deploy", None),
        setup_calls=getattr(config, "setup_calls", None),
        external=getattr(config, "external", None),
    )

    spec = spec_for(policy.method_name)
    backend_label, model_label, approach = backend_labels(getattr(config, "llm", None))
    console.print(render_start_panel(
        spec,
        contract=config.contract_name,
        iterations=config.max_iterations,
        backend_label=backend_label,
        model_label=model_label,
        approach=approach,
        strategies=len(GENERATION_STRATEGIES),
        function_groups=policy.num_groups,
    ))

    if not fuzzer.compile():
        console.print("[red]Compilation failed. Aborting.[/red]")
        return [], {"summary": {}, "iterations": [], "bugs": []}

    # Build features + encoder AFTER compile so we can use the AST (deterministic
    # ground truth) instead of regex on raw source. State_dim is structural and
    # doesn't change between regex and AST, so the throwaway `enc_probe` in the
    # runner can stay on the regex path without breaking policy construction.
    bc_meta = fuzzer._bc_meta
    if bc_meta is not None and bc_meta.ast is not None:
        features = ContractFeatures.from_ast(bc_meta.ast, contract_abi)
    else:
        features = ContractFeatures.from_source(contract_source, contract_abi)
    encoder = BaselineStateEncoder(
        features, num_groups=policy.num_groups, max_iterations=config.max_iterations
    )

    found_bugs: list[dict] = []
    run_records: list[dict] = []
    total_reward = 0.0
    run_id = 0
    start_iteration = 0

    # ── Iteration-level checkpoint restore ────────────────────────────────────
    # Same inner-resume layer sscfuzz uses (see fuzz/checkpoint.py). The runner
    # sets checkpoint_path/every so a baseline interrupted mid-contract resumes
    # from the last flush. All components are built above; restore here.
    _ckpt_path = getattr(config, "checkpoint_path", None)
    _ckpt_every = int(getattr(config, "checkpoint_every", 0) or 0)
    _records_path = _ckpt.records_path(_ckpt_path) if (_ckpt_path and _ckpt_every > 0) else None
    if _ckpt_path and _ckpt_every > 0:
        _ck = _ckpt.load(_ckpt_path)
        if _ck is not None:
            start_iteration = _ck["iteration"]
            run_id = _ck["run_id"]
            total_reward = _ck["total_reward"]
            # run_records live in the sidecar JSONL, truncated to completed iters.
            run_records = _ckpt.load_records(_records_path, start_iteration)
            found_bugs = _ck["found_bugs"]
            fuzzer.restore_checkpoint_state(_ck["fuzzer"])
            encoder.restore_checkpoint_state(_ck["encoder"])
            policy.restore_checkpoint_state(_ck["policy"])
            _ckpt.restore_rng(_ck.get("rng"))
            console.print(
                f"[green]▶ Resumed {policy.method_name} from checkpoint at "
                f"iteration {start_iteration}/{config.max_iterations}[/green]"
            )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=not debug,
        console=console,
    ) as progress:
        task = progress.add_task(
            f"{policy.method_name}...", total=config.max_iterations, completed=start_iteration
        )
        for iteration in range(start_iteration, config.max_iterations):
            _iter_t0 = time.perf_counter()
            state = encoder.encode()
            fuzz_input, action_meta = policy.select_input(state, iteration)

            action_str = (
                f" {spec.action_label}={action_meta.get('group_name', '?')}"
                if spec.action_label else ""
            )
            progress.update(
                task,
                description=f"[{iteration + 1}/{config.max_iterations}] "
                f"{policy.method_name}{action_str}",
            )

            result = fuzzer.run_input(fuzz_input, strategy=config.reward_strategy, debug=debug)
            # Mode-aware reward: policies that mutate (LLMFuzz) set mode="mutate" +
            # seed_branches in action_meta so the novelty bonus applies; generation-
            # only policies omit these keys → mode="generate"/seed_branches=None
            # (unchanged behavior).
            reward = compute_reward(
                result,
                strategy=config.reward_strategy,
                seed_branches=action_meta.get("seed_branches"),
                mode=action_meta.get("mode", "generate"),
            )
            total_reward += reward

            # Optional hook: policies that maintain internal state (e.g. LLM history)
            # implement on_result(fuzz_input, result, reward, action_meta) to update
            # themselves right after seeing the fuzzer's response.
            if hasattr(policy, 'on_result'):
                policy.on_result(fuzz_input, result, reward, action_meta)

            next_state = encoder.encode()
            encoder.update(
                group_idx=int(action_meta.get("group_idx", 0)),
                result=result,
                reward=reward,
                fn_names_used=_fn_names_in_input(fuzz_input),
            )
            policy.update(state, action_meta, reward, next_state, done=False)

            if debug:
                console.print(
                    f"[dim]iter={iteration}{action_str} "
                    f"reward={reward:+.2f} cov={result.coverage:.2%} "
                    f"reason={result.raw_reason or 'ok'}[/dim]"
                )

            tok_stats = policy.token_stats()
            tok_in = tok_stats.input_tokens if tok_stats else 0
            tok_out = tok_stats.output_tokens if tok_stats else 0

            fuzzing_output = build_fuzzing_output(reward, result)
            # Learning-process trace: cumulative reward/coverage/bugs + per-iter
            # wallclock (+ DQN telemetry when the policy exposes it).
            _tele = policy.learning_telemetry() if hasattr(policy, "learning_telemetry") else {}
            _rec = build_run_record(
                spec,
                run_id=run_id,
                iteration=iteration,
                cum_reward=total_reward,
                cum_unique_bc_branches=fuzzer.unique_bc_branches,
                # +1 for this iteration's bug (found_bugs is appended below).
                cum_bugs=len(found_bugs) + (1 if result.bug_signal_found else 0),
                wall_ms=(time.perf_counter() - _iter_t0) * 1000.0,
                epsilon=_tele.get("epsilon"),
                td_loss=_tele.get("td_loss"),
                q_chosen=_tele.get("q_chosen"),
                # Action descriptor — gated by spec.log_action_kind. The shared
                # meta keys cover every baseline; LLMFuzz also carries `strategy`
                # + llm_prompt/llm_response/fallback for its strategy-kind record.
                group_idx=action_meta.get("group_idx"),
                group_name=action_meta.get("group_name"),
                fn_name=action_meta.get("fn_name"),
                strategy=action_meta.get("strategy"),
                mode=action_meta.get("mode"),
                mutation_strategy=action_meta.get("mutation_strategy"),
                llm_prompt=action_meta.get("llm_prompt", ""),
                llm_response=action_meta.get("llm_response", ""),
                fallback=action_meta.get("fallback"),
                fallback_reason=action_meta.get("fallback_reason"),
                fuzz_input=fuzz_input.to_dict(),
                fuzzing_output=fuzzing_output,
                tokens={
                    "cumulative_input_tokens": tok_in,
                    "cumulative_output_tokens": tok_out,
                },
            )
            run_records.append(_rec)
            if _records_path is not None:
                _ckpt.append_record(_records_path, _rec)
            run_id += 1

            if result.bug_signal_found:
                found_bugs.append(build_bug_record(
                    spec,
                    iteration=iteration,
                    group_idx=action_meta.get("group_idx"),
                    group_name=action_meta.get("group_name"),
                    fn_name=action_meta.get("fn_name"),
                    strategy=action_meta.get("strategy"),
                    mode=action_meta.get("mode"),
                    mutation_strategy=action_meta.get("mutation_strategy"),
                    bug_type=result.bug_type,
                    fuzz_input=fuzz_input.to_dict(),
                    revert_reason=result.revert_reason,
                    trace=result.trace,
                ))
                console.print(
                    f"\n[red bold]BUG[/red bold] iter={iteration} {result.bug_type}"
                )

            progress.advance(task)

            # ── Periodic checkpoint flush (disk-only, every checkpoint_every) ──
            _done = iteration + 1
            if (_ckpt_every > 0 and _ckpt_path
                    and _done < config.max_iterations
                    and _done % _ckpt_every == 0):
                _ckpt.save(_ckpt_path, {
                    "iteration": _done,
                    "run_id": run_id,
                    "total_reward": total_reward,
                    # run_records → sidecar JSONL (append_record), not this blob.
                    "found_bugs": found_bugs,
                    "fuzzer": fuzzer.checkpoint_state(),
                    "encoder": encoder.checkpoint_state(),
                    "policy": policy.checkpoint_state(),
                    "rng": _ckpt.rng_state(),
                })

    # ── Final keep-checkpoint (clean completion only) ─────────────────────────
    # Reached only when the loop ran to the end (Ctrl+C / crash propagates out,
    # leaving the last periodic flush for crash recovery). One complete checkpoint
    # at the true last iteration (config.max_iterations, e.g. 110 — not the last
    # every-N flush) so a later higher-budget run continues. `iteration` may be
    # unbound here (empty range on an already-complete resume), so use max_iterations.
    if _ckpt_every > 0 and _ckpt_path and getattr(config, "keep_checkpoint", False):
        _ckpt.save(_ckpt_path, {
            "iteration": config.max_iterations,
            "run_id": run_id,
            "total_reward": total_reward,
            "found_bugs": found_bugs,
            "fuzzer": fuzzer.checkpoint_state(),
            "encoder": encoder.checkpoint_state(),
            "policy": policy.checkpoint_state(),
            "rng": _ckpt.rng_state(),
        })
        console.print(
            f"[dim]✔ kept final checkpoint at iteration {config.max_iterations} "
            f"(re-run with a higher --iterations to continue)[/dim]"
        )

    cov = fuzzer.measure_coverage()
    tok_stats = policy.token_stats()
    total_in = tok_stats.input_tokens if tok_stats else 0
    total_out = tok_stats.output_tokens if tok_stats else 0

    # Per-method extras (gated by `spec`): corpus = MADFuzz's LLM seed pool;
    # fallback = LLMFuzz's LLM-retry-exhaustion count; seed_pool_ok = MADFuzz's
    # one-shot seed-gen status (True ok / False failed / None disabled).
    corpus_size = len(policy.seed_pool) if hasattr(policy, "seed_pool") else None
    fallback_used = getattr(policy, "fallback_count", None)
    console.print(render_done_panel(
        spec,
        total_reward=total_reward,
        cov=cov,
        bugs_found=len(found_bugs),
        corpus_size=corpus_size,
        fallback_used=fallback_used,
        fallback_total=config.max_iterations if fallback_used is not None else None,
        seed_pool_ok=getattr(policy, "seed_gen_ok", None),
        tokens_in=total_in,
        tokens_out=total_out,
    ))

    full_log = {
        "summary": build_run_summary(
            spec,
            cov=cov,
            run_records=run_records,
            total_reward=total_reward,
            total_iterations=config.max_iterations,
            total_bugs=len(found_bugs),
            tokens_in=total_in,
            tokens_out=total_out,
            llm_fallback_count=fallback_used,
            backend_label=backend_label,
            model_label=model_label,
            approach=approach,
            corpus_size=corpus_size,
            seed_pool_ok=getattr(policy, "seed_gen_ok", None),
        ),
        "iterations": run_records,
        "bugs": found_bugs,
    }
    return found_bugs, full_log


def write_outputs(
    *,
    output_path: str | None,
    run_log_path: str | None,
    bugs: list[dict],
    full_log: dict,
    method: str = "baseline",
    contract: str = "",
    console: Console | None = None,
) -> None:
    """Persist per-run bugs.json (with summary header) and detailed run log."""
    console = console or Console()
    # Reuse the same builder as main.py so schema stays consistent across all methods.
    from ...main import build_bugs_payload
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(
            build_bugs_payload(bugs, full_log, method=method, contract=contract),
            indent=2,
        ))
        console.print(f"Bugs report written to [cyan]{p}[/cyan]")
    if run_log_path:
        p = Path(run_log_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(full_log, indent=2))
        console.print(f"Run log written to [cyan]{p}[/cyan]")
