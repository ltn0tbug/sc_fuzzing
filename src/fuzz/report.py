"""Unified console reporting — Start/Done panels + default output path.

One renderer for every method so the console format can't drift between
`sc-fuzz sscfuzz` (orchestrator.py) and the baselines (baselines/common/loop.py).

Each method declares its field set **once** in `REPORT_SPECS`. The renderer
always emits the universal fields and emits a *gated* field only when the
method's spec flag is True — so "does LLMFuzz print Function groups?" has a
single answer that lives in one place. Adding a field = one bool on
`ReportSpec` + one branch in the renderer; every method stays in sync because
they all read the same spec.

Field matrix (gated fields only — Method/Contract/Iterations and
Reward/Coverage/Bugs are always shown):

    Start:   backend  strategies  function_groups
    sscfuzz     Y         Y(=14)        -
    rlfuzz      -          -            Y
    madfuzz     Y          -            Y
    randomfuzz  -          -            -
    llmfuzz     Y         Y(=7)         -

    Done:    corpus       fallback   seed_pool_gen   tokens
    sscfuzz   Y(corpus)      Y            -            Y
    rlfuzz      -            -            -            -
    madfuzz   Y(seed pool)   -           Y             Y
    randomfuzz  -            -            -            -
    llmfuzz     -            Y            -            Y

The **run-log JSON** and **bug-report JSON** follow the same one-place model.
A per-iteration run record carries the universal fields (run_id / iteration /
method / fuzz_input / fuzzing_output) plus method-gated extras; the bug record
carries the universal bug fields plus the same action/lineage extras:

    run record       action_kind   llm_io   fallback   lineage   tokens
    sscfuzz          rl            Y        Y          Y         Y
    rlfuzz           group         -        -          -         -
    madfuzz          group         -        -          -         Y
    randomfuzz       random        -        -          -         -
    llmfuzz          strategy      Y        Y          -         Y

`action_kind` selects which descriptor keys a record emits:
    rl       → mode / strategy / mutation_strategy     (RL picks a generation or mutation strategy)
    group    → group_idx / group_name / fn_name  (group-DQN baselines)
    strategy → strategy / fn_name             (LLMFuzz rotates a strategy)
    random   → fn_name                        (RandomFuzz — no group/strategy)

Per-run `tokens` + summary `token_usage` are gated by `show_tokens`; summary
`llm_fallback_*` by `log_fallback`; summary `random_input_*` by
`log_random_inject`.

Learning process (all methods): every run record carries a universal `learning`
block — cum_reward / cum_unique_bc_branches / cum_bugs / wall_ms — plus, when
`log_learning_rl` (sscfuzz + the two group-DQN baselines), epsilon / td_loss /
q_chosen. `build_run_summary` folds these into a `learning_curve` block
(`_learning_curve`): compact coverage/reward curves + convergence scalars
(first_bug_iter, coverage_saturation_iter, bc_branches_at_quartiles, and — RL —
final_epsilon, mean_loss_last_decile).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from rich.panel import Panel

from .config import LLMConfig


@dataclass(frozen=True)
class ReportSpec:
    """Per-method console field declaration. One instance per method, all
    living in `REPORT_SPECS` keyed by the lowercase method id."""

    method: str          # lowercase id — used in filenames + REPORT_SPECS key
    display: str         # name shown on the Starting panel's first line
    # Human label for what the policy picked each iteration (progress/debug
    # lines). RL group-DQN methods pick a function "group"; LLMFuzz picks a
    # "strategy"; RandomFuzz picks nothing (None → no label shown, it's just a
    # random function sequence). The run-log JSON keeps the neutral `group_name`
    # key regardless.
    action_label: str | None = "group"

    # ── Start-panel gated fields ──────────────────────────────────────────────
    show_backend: bool = False
    show_strategies: bool = False
    show_function_groups: bool = False

    # ── Done-panel gated fields ───────────────────────────────────────────────
    show_corpus: bool = False
    corpus_label: str = "Corpus Size"
    show_fallback: bool = False
    show_seed_pool_gen: bool = False
    show_tokens: bool = False

    # ── Run-log / bug-report gated fields ─────────────────────────────────────
    # Which action-descriptor keys a run/bug record emits (see module docstring):
    #   "rl" | "group" | "strategy" | "random".
    log_action_kind: str = "group"
    log_llm_io: bool = False        # per-run llm_prompt + llm_response
    log_fallback: bool = False      # per-run fallback + fallback_reason (+ summary rate)
    log_lineage: bool = False       # per-run/bug lineage_signature + lineage_depth
    log_random_inject: bool = False  # summary random_inputs_used + random_input_rate
    # DQN "learning process" telemetry: per-run epsilon / td_loss / q_chosen +
    # summary final_epsilon / mean_loss_last_decile. True only for the DQN methods
    # (sscfuzz + the two group-DQN baselines); LLMFuzz/RandomFuzz have no learner.
    log_learning_rl: bool = False


REPORT_SPECS: dict[str, ReportSpec] = {
    "sscfuzz": ReportSpec(
        "sscfuzz", "SScFuzz",
        show_backend=True, show_strategies=True,
        show_corpus=True, show_fallback=True, show_tokens=True,
        log_action_kind="rl", log_llm_io=True, log_fallback=True,
        log_lineage=True, log_random_inject=True, log_learning_rl=True,
    ),
    "rlfuzz": ReportSpec(
        "rlfuzz", "RLFuzz",
        show_function_groups=True,
        log_action_kind="group", log_learning_rl=True,
    ),
    "madfuzz": ReportSpec(
        "madfuzz", "MADFuzz",
        show_backend=True, show_function_groups=True,
        show_corpus=True, corpus_label="Corpus Size",
        show_seed_pool_gen=True, show_tokens=True,
        log_action_kind="group", log_learning_rl=True,
    ),
    "randomfuzz": ReportSpec(
        "randomfuzz", "RandomFuzz", action_label=None,
        log_action_kind="random",
    ),
    "llmfuzz": ReportSpec(
        "llmfuzz", "LLMFuzz", action_label="strategy",
        show_backend=True, show_strategies=True,
        show_fallback=True, show_tokens=True,
        log_action_kind="strategy", log_llm_io=True, log_fallback=True,
    ),
    # FinanceFuzz competitor: evolutionary engine (no RL/LLM) + financial-property
    # oracle. "generation" labels the GA generation in progress lines; records carry
    # only fn_name (neutral, like RandomFuzz) — the bug taxonomy lives in bug_type.
    "financefuzz": ReportSpec(
        "financefuzz", "FinanceFuzz", action_label="generation",
        log_action_kind="random",
    ),
}


def spec_for(method: str) -> ReportSpec:
    """Look up a method's ReportSpec by (case-insensitive) id."""
    return REPORT_SPECS[method.lower()]


def default_output_path(method: str, *, base: str = "output") -> str:
    """Default bug-report location: output/{method}_{YYYYMMDD-HHMMSS}.json."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{base}/{method}_{ts}.json"


def default_run_log_path(method: str, *, base: str = "output") -> str:
    """Default run-log location: output/{method}_run_log_{ts}.json."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{base}/{method}_run_log_{ts}.json"


def resolve_run_log_path(
    arg: str | None, method: str, *, bug_report_only: bool = False
) -> str | None:
    """Resolve where the full run log should be written (or None to skip).

    bug_report_only → None (the only way to suppress the run log).
    --run-log-path given → that explicit path.
    otherwise (default) → output/{method}_run_log_{ts}.json.
    """
    if bug_report_only:
        return None
    if arg:
        return arg
    return default_run_log_path(method)


def backend_labels(
    llm: LLMConfig | None, *, detected_model: str | None = None
) -> tuple[str, str, str]:
    """Render (backend_label, model_label, approach) from an LLMConfig.

    `detected_model` lets the caller override the model name for llama-cpp,
    where the actual served model is fetched from the server at startup
    (the config only holds a placeholder).
    """
    if llm is None:
        return ("", "", "")
    if llm.backend == "llama-cpp":
        backend_label = f"llama-cpp ({llm.backend_url})"
        # llama-cpp serves whatever model was loaded at startup; the config's
        # `model` is just a placeholder. Detect the real name from the server so
        # every method's panel shows the same thing (callers may pass it in to
        # avoid a second round-trip). Fall back to the config name if the server
        # is unreachable.
        if detected_model is None:
            try:
                from .llm.agent import _LlamaCppBackend
                detected_model = _LlamaCppBackend(url=llm.backend_url).detect_model_name()
            except Exception:
                detected_model = None
        model_label = detected_model or llm.model
    else:
        backend_label = {
            "anthropic": "Anthropic API",
            "claude-code": "Claude Code CLI",
        }.get(llm.backend, llm.backend)
        model_label = detected_model or llm.model
    return (backend_label, model_label, llm.approach)


def render_start_panel(
    spec: ReportSpec,
    *,
    contract: str,
    iterations: int,
    backend_label: str | None = None,
    model_label: str | None = None,
    approach: str | None = None,
    strategies: int | None = None,
    function_groups: int | None = None,
) -> Panel:
    """Build the 'Starting' panel for any method, gated by `spec`."""
    lines = [
        f"[bold cyan]{spec.display}[/bold cyan]",
        f"Contract: [yellow]{contract}[/yellow]",
        f"Iterations: [yellow]{iterations}[/yellow]",
    ]
    if spec.show_backend and backend_label:
        # Split across lines (model names + server URLs get long) so the panel
        # stays narrow instead of stretching to one very wide line.
        lines.append(f"LLM Backend: [bold]{backend_label}[/bold]")
        lines.append(f"  model=[cyan]{model_label}[/cyan]")
        lines.append(f"  approach=[magenta]{approach}[/magenta]")
    if spec.show_strategies and strategies is not None:
        lines.append(f"Strategies: [yellow]{strategies}[/yellow]")
    if spec.show_function_groups and function_groups is not None:
        lines.append(f"Function groups: [yellow]{function_groups}[/yellow]")
    return Panel.fit("\n".join(lines), title="Starting")


def render_done_panel(
    spec: ReportSpec,
    *,
    total_reward: float,
    cov,
    bugs_found: int,
    corpus_size: int | None = None,
    fallback_used: int | None = None,
    fallback_total: int | None = None,
    seed_pool_ok: Optional[bool] = None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
) -> Panel:
    """Build the 'Done' panel for any method, gated by `spec`.

    `cov` is a CoverageStats (bc_branches_hit / bc_branches_total / bc_ratio).
    `seed_pool_ok`: True=ok, False=failed, None=disabled (only read when
    `spec.show_seed_pool_gen`).
    """
    lines = [
        f"Total Reward: [yellow]{total_reward:.2f}[/yellow]",
        f"Coverage: [blue]{cov.bc_branches_hit}/{cov.bc_branches_total} "
        f"({cov.bc_ratio:.1%})[/blue]",
    ]
    if spec.show_corpus and corpus_size is not None:
        lines.append(f"{spec.corpus_label}: [magenta]{corpus_size}[/magenta]")
    lines.append(f"Bugs Found: [red bold]{bugs_found}[/red bold]")
    if spec.show_fallback and fallback_total is not None:
        used = fallback_used or 0
        rate = (used / fallback_total) if fallback_total else 0.0
        lines.append(
            f"Fallback: [yellow]{used}/{fallback_total} ({rate:.1%})[/yellow]"
        )
    if spec.show_seed_pool_gen:
        if seed_pool_ok is None:
            status = "[dim]disabled[/dim]"
        elif seed_pool_ok:
            status = "[green]ok[/green]"
        else:
            status = "[red]failed[/red]"
        lines.append(f"Seed-pool gen: {status}")
    if spec.show_tokens and tokens_in is not None:
        lines.append(
            f"Tokens: [dim]in={tokens_in:,} out={tokens_out or 0:,} "
            f"total={tokens_in + (tokens_out or 0):,}[/dim]"
        )
    return Panel.fit("\n".join(lines), title="[bold green]Done[/bold green]")


# ── JSON output builders (run log + bug report) ───────────────────────────────
# Both run-log call sites (orchestrator.py for sscfuzz, baselines/common/loop.py for the
# 4 baselines) funnel through these so the field matrix lives in one place — the
# JSON analogue of render_*_panel. A record always carries the universal fields;
# everything else is gated by the method's `spec`.


def _action_fields(spec: ReportSpec, **kw) -> dict:
    """Action-descriptor keys for a run/bug record, selected by log_action_kind."""
    kind = spec.log_action_kind
    if kind == "rl":
        return {"mode": kw.get("mode"), "strategy": kw.get("strategy"),
                "mutation_strategy": kw.get("mutation_strategy")}
    if kind == "strategy":
        # LLMFuzz now selects over the generation+mutation roster, so log mode +
        # mutation_strategy (like the "rl" kind) so analysis can split gen vs mut.
        # For a mutation iteration `strategy` is the seed's generation context.
        return {"strategy": kw.get("strategy"), "fn_name": kw.get("fn_name"),
                "mode": kw.get("mode"), "mutation_strategy": kw.get("mutation_strategy")}
    if kind == "random":
        return {"fn_name": kw.get("fn_name")}
    # default "group"
    return {"group_idx": kw.get("group_idx"), "group_name": kw.get("group_name"),
            "fn_name": kw.get("fn_name")}


def build_fuzzing_output(reward: float, result) -> dict:
    """The per-iteration `fuzzing_output` record — built in ONE place so the sscfuzz
    (orchestrator.py) and baseline (baselines/common/loop.py) producers stay byte-identical.

    Detection keys carry a precision/recall split:
      - `signal_found`    (recall)   — any BUG_SIGNAL line appeared.
      - `high_bug_signal_found`(precision) — a tier=high signal proved a net profit/loss;
                                        surfaces as `signal=High` in the LLM history.
      - `novel_path`                 — this run's exploit path was novel (drove the bug reward).
      - `signals`                    — the structured [{name,tier,asset,token_address,total_asset,target_asset,amount}]
                                       list: the source of truth that supersedes `bug_type`.
    `bug_found` / `bug_type` are LEGACY aliases kept so the (not-yet-migrated) analysis
    layer keeps running; drop them in the analysis pass. Per-line coverage id/count dumps
    are intentionally omitted (nothing at runtime reads them); `lines_this_run` /
    `functions_this_run` stay because `utils/build_summary_xlsx.py` unions them into the
    cumulative line/function coverage the run-log otherwise lacks.
    """
    return {
        "reward": round(reward, 4),
        # Bytecode-level branch coverage (drives the reward signal)
        "new_bc_branches": result.new_bc_branches,
        "coverage": round(result.coverage, 6),
        "bc_branches_total": result.bc_branches_total,
        # Source-level branch coverage (log-only — matches forge convention)
        "new_branches": result.new_branches,
        "branches_total": result.branches_total,
        # Line coverage (log-only — build_summary_xlsx unions lines_this_run)
        "new_lines": result.new_lines,
        "lines_total": result.lines_total,
        "lines_this_run": sorted(result.lines_this_run),
        # Function coverage (log-only — build_summary_xlsx unions functions_this_run)
        "new_functions": result.new_functions,
        "functions_total": result.functions_total,
        "functions_this_run": sorted(result.functions_this_run),
        # Test outcome
        "forge_status": result.forge_status,
        "revert_reason": result.revert_reason,
        "raw_reason": result.raw_reason,
        "gas_used": result.gas_used,
        # Detection outcome (precision / recall) — see docstring
        "signal_found": result.bug_signal_found,
        "high_bug_signal_found": result.high_bug_signal_found,
        "novel_path": bool(result.new_exploit_path),
        "signals": result.bug_signals,
        "bug_type": result.bug_type,             # legacy alias (deferred removal)
        "bug_found": result.bug_signal_found,    # legacy alias of signal_found (deferred removal)
        "decoded_logs": result.decoded_logs,
    }


def build_run_record(
    spec: ReportSpec,
    *,
    run_id: int,
    iteration: int,
    fuzz_input: dict,
    fuzzing_output: dict,
    mode: str | None = None,
    strategy: str | None = None,
    mutation_strategy: str | None = None,
    group_idx: int | None = None,
    group_name: str | None = None,
    fn_name: str | None = None,
    llm_prompt: str = "",
    llm_response: str = "",
    fallback: bool | None = None,
    fallback_reason: str | None = None,
    lineage_signature: str | None = None,
    lineage_depth: int | None = None,
    tokens: dict | None = None,
    cum_reward: float | None = None,
    cum_unique_bc_branches: int | None = None,
    cum_bugs: int | None = None,
    wall_ms: float | None = None,
    epsilon: float | None = None,
    td_loss: float | None = None,
    q_chosen: float | None = None,
) -> dict:
    """Assemble one per-iteration run-log record, gated by `spec`.

    Universal keys (always): run_id, iteration, method, fuzz_input,
    fuzzing_output, and a `learning` block tracing the run's progress (cumulative
    reward / unique bc-branches / bugs + per-iter wall_ms). Gated: action
    descriptor (log_action_kind), fallback, lineage, llm_prompt/llm_response,
    tokens, and — for DQN methods (log_learning_rl) — epsilon/td_loss/q_chosen
    inside the `learning` block.
    """
    rec: dict = {"run_id": run_id, "iteration": iteration, "method": spec.method}
    rec.update(_action_fields(
        spec, mode=mode, strategy=strategy, mutation_strategy=mutation_strategy,
        group_idx=group_idx, group_name=group_name, fn_name=fn_name,
    ))
    # ── Learning-process trace (universal + RL-gated) ─────────────────────────
    learning: dict = {
        "cum_reward": round(cum_reward, 4) if cum_reward is not None else None,
        "cum_unique_bc_branches": cum_unique_bc_branches,
        "cum_bugs": cum_bugs,
        "wall_ms": round(wall_ms, 1) if wall_ms is not None else None,
    }
    if spec.log_learning_rl:
        learning["epsilon"] = round(epsilon, 4) if epsilon is not None else None
        learning["td_loss"] = round(td_loss, 6) if td_loss is not None else None
        learning["q_chosen"] = round(q_chosen, 4) if q_chosen is not None else None
    rec["learning"] = learning
    if spec.log_fallback:
        rec["fallback"] = bool(fallback)
        rec["fallback_reason"] = fallback_reason
    if spec.log_lineage:
        rec["lineage_signature"] = lineage_signature
        rec["lineage_depth"] = lineage_depth
    if spec.log_llm_io:
        rec["llm_prompt"] = llm_prompt
        rec["llm_response"] = llm_response
    rec["fuzz_input"] = fuzz_input
    rec["fuzzing_output"] = fuzzing_output
    if spec.show_tokens and tokens is not None:
        rec["tokens"] = tokens
    return rec


def build_bug_record(
    spec: ReportSpec,
    *,
    iteration: int,
    bug_type,
    fuzz_input: dict,
    revert_reason,
    trace: str = "",
    mode: str | None = None,
    strategy: str | None = None,
    mutation_strategy: str | None = None,
    group_idx: int | None = None,
    group_name: str | None = None,
    fn_name: str | None = None,
    lineage_signature: str | None = None,
    lineage_depth: int | None = None,
) -> dict:
    """Assemble one bug-report record, gated by `spec` (same action/lineage
    model as build_run_record)."""
    rec: dict = {"iteration": iteration, "method": spec.method}
    rec.update(_action_fields(
        spec, mode=mode, strategy=strategy, mutation_strategy=mutation_strategy,
        group_idx=group_idx, group_name=group_name, fn_name=fn_name,
    ))
    if spec.log_lineage:
        rec["lineage_signature"] = lineage_signature
        rec["lineage_depth"] = lineage_depth
    rec["bug_type"] = bug_type
    rec["input"] = fuzz_input
    rec["revert_reason"] = revert_reason
    rec["trace"] = trace[:500] if isinstance(trace, str) else trace
    return rec


def _sample_curve(pairs: list[tuple[int, float]], k: int = 20) -> list[list]:
    """Downsample [(iteration, value), …] to ≤k evenly-spaced points (keeps the
    last). Keeps the learning curve compact in JSON while staying plottable."""
    n = len(pairs)
    if n <= k:
        return [[i, v] for i, v in pairs]
    idxs = sorted({round(j * (n - 1) / (k - 1)) for j in range(k)})
    return [[pairs[i][0], pairs[i][1]] for i in idxs]


def _learning_curve(spec: ReportSpec, run_records: list[dict], total_iterations: int) -> dict:
    """Cross-method 'learning process' summary derived from the per-run `learning`
    blocks: compact curves + convergence scalars comparable across methods.

    - bc_coverage_curve / cum_reward_curve: ≤20-point [iteration, value] samples.
    - first_bug_iter: iteration of the first BUG_SIGNAL (None if none).
    - coverage_saturation_iter: iteration of the last unique-bc-branch gain
      (when coverage learning plateaus).
    - bc_branches_at_quartiles: cumulative unique bc-branches at 25/50/75/100%.
    - RL methods only: final_epsilon, mean_loss_last_decile.
    """
    lrn = [(r.get("iteration"), r.get("learning") or {}, r.get("fuzzing_output") or {})
           for r in run_records]
    if not lrn:
        return {}
    cov_pairs = [(it, l.get("cum_unique_bc_branches"))
                 for it, l, _ in lrn if l.get("cum_unique_bc_branches") is not None]
    rew_pairs = [(it, l.get("cum_reward"))
                 for it, l, _ in lrn if l.get("cum_reward") is not None]

    first_bug_iter = next(
        (it for it, _, fo in lrn if fo.get("signal_found", fo.get("bug_found"))), None)

    # Coverage saturation = iteration where cumulative coverage last increased.
    saturation_iter = None
    prev = None
    for it, v in cov_pairs:
        if prev is None or v > prev:
            saturation_iter = it
        prev = v

    def _cov_at(frac: float):
        if not cov_pairs:
            return None
        target = frac * total_iterations
        val = cov_pairs[0][1]
        for it, v in cov_pairs:
            if it <= target:
                val = v
            else:
                break
        return val

    out: dict = {
        "bc_coverage_curve": _sample_curve(cov_pairs),
        "cum_reward_curve": _sample_curve(rew_pairs),
        "first_bug_iter": first_bug_iter,
        "coverage_saturation_iter": saturation_iter,
        "bc_branches_at_quartiles": {
            "q25": _cov_at(0.25), "q50": _cov_at(0.50),
            "q75": _cov_at(0.75), "q100": _cov_at(1.0),
        },
    }
    if spec.log_learning_rl:
        eps = [l.get("epsilon") for _, l, _ in lrn if l.get("epsilon") is not None]
        losses = [l.get("td_loss") for _, l, _ in lrn if l.get("td_loss") is not None]
        out["final_epsilon"] = round(eps[-1], 4) if eps else None
        if losses:
            tail = losses[max(0, len(losses) - max(1, len(losses) // 10)):]
            out["mean_loss_last_decile"] = round(sum(tail) / len(tail), 6)
        else:
            out["mean_loss_last_decile"] = None
    return out


def build_run_summary(
    spec: ReportSpec,
    *,
    cov,
    run_records: list[dict],
    total_reward: float,
    total_iterations: int,
    total_bugs: int,
    tokens_in: int = 0,
    tokens_out: int = 0,
    llm_fallback_count: int | None = None,
    random_inputs_used: int | None = None,
    backend_label: str | None = None,
    model_label: str | None = None,
    approach: str | None = None,
    corpus_size: int | None = None,
    seed_pool_ok: Optional[bool] = None,
    extra: dict | None = None,
) -> dict:
    """Assemble the run-log `summary` block, gated by `spec`.

    Coverage aggregation is universal; llm_backend + token_usage are gated by
    show_backend / show_tokens, corpus_size by show_corpus, seed_pool_gen by
    show_seed_pool_gen, llm_fallback_* by log_fallback, random_input_* by
    log_random_inject. `extra` merges any method-specific scalars a caller
    wants appended. Mirrors the Done panel's gated fields into JSON.
    """
    summary: dict = {
        "method": spec.method,
        "total_iterations": total_iterations,
        "total_reward": round(total_reward, 4),
        "total_new_bc_branches": sum(r["fuzzing_output"]["new_bc_branches"] for r in run_records),
        "total_coverage_bc_branches": cov.bc_branches_hit,
        "total_bc_branches": cov.bc_branches_total,
        "bc_coverage_ratio": round(cov.bc_ratio, 6),
        "total_new_branches": sum(r["fuzzing_output"]["new_branches"] for r in run_records),
        "total_coverage_branches": cov.branches_hit,
        "total_branches": cov.branches_total,
        "coverage_ratio": round(cov.ratio, 6),
        # Fork only: the recompiled artifact drifted from the on-chain bytecode, so
        # the SOURCE tier (coverage_ratio/total_branches) is untrustworthy; bc +
        # function coverage are on-chain-anchored and stay valid. EDA can exclude/
        # annotate these rows. Always False for inline (own freshly-deployed code).
        "coverage_unreliable": bool(getattr(cov, "coverage_unreliable", False)),
        "total_bugs_found": total_bugs,
        # Cross-method "learning process" — compact curves + convergence scalars
        # derived from the per-run `learning` blocks (see _learning_curve).
        "learning_curve": _learning_curve(spec, run_records, total_iterations),
    }
    if spec.show_backend and backend_label:
        summary["llm_backend"] = {
            "backend": backend_label,
            "model": model_label,
            "approach": approach,
        }
    # Corpus = sscfuzz's gen×mut working set OR madfuzz's one-shot LLM seed pool;
    # seed_pool_gen = madfuzz's one-shot LLM seed-gen status (ok/failed/disabled).
    if spec.show_corpus and corpus_size is not None:
        summary["corpus_size"] = corpus_size
    if spec.show_seed_pool_gen:
        summary["seed_pool_gen"] = (
            "disabled" if seed_pool_ok is None
            else "ok" if seed_pool_ok else "failed"
        )
    if extra:
        summary.update(extra)
    if spec.log_fallback and llm_fallback_count is not None:
        summary["llm_fallback_count"] = llm_fallback_count
        summary["llm_fallback_rate"] = (
            round(llm_fallback_count / total_iterations, 4) if total_iterations else 0.0
        )
    if spec.log_random_inject and random_inputs_used is not None:
        summary["random_inputs_used"] = random_inputs_used
        summary["random_input_rate"] = (
            round(random_inputs_used / total_iterations, 4) if total_iterations else 0.0
        )
    if spec.show_tokens:
        summary["token_usage"] = {
            "input_tokens": tokens_in,
            "output_tokens": tokens_out,
            "total_tokens": tokens_in + tokens_out,
        }
    return summary
