"""SScFuzz iteration driver — the RL+LLM fuzzing loop, split out of `main.py`.

`run_fuzzing_loop` is the SScFuzz method entry point (the parallel of the
baselines' `common/loop.py`); `main.py` is now just the click CLI that calls
it, and `experiment/run/registry.py` calls it directly. `main.py` re-exports
`run_fuzzing_loop` / `build_bugs_payload`, so `from fuzz.main import
run_fuzzing_loop` (registry) and `from ...main import build_bugs_payload`
(baselines loop) keep working.
"""

import datetime as _dt
import logging
import os
import random
import time

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import checkpoint as _ckpt
from .config import FuzzerConfig
from .fuzzer.arg_sampling import build_address_pool
from .fuzzer.foundry import FoundryFuzzer
from .fuzzer.mutator import CorpusEntry, LLMMutator
from .llm.random_gen import random_fuzz_input
from .fuzzer.reward import _HEURISTIC_SIGNAL_SCORE, _HIGH_SIGNAL_SCORE, compute_reward
from .fuzzer.state import ContractFeatures, StateEncoder
from .llm.agent import FuzzInput, TokenUsage
from .llm.generator import LLMGenerator
from .llm.strategies import MUTATION_STRATEGIES, GENERATION_STRATEGIES
from .report import (
    backend_labels,
    build_bug_record,
    build_fuzzing_output,
    build_run_record,
    build_run_summary,
    render_done_panel,
    render_start_panel,
    spec_for,
)
from .rl import make_controller

console = Console()
logger = logging.getLogger(__name__)

# RL Iter 6 builds a compact per-run action TABLE from the active roster (see
# run_fuzzing_loop) instead of a fixed 0..gen..mut layout — no module-level width
# constants needed; the table's length IS action_dim.

# Field-gating spec for sscfuzz's console panels + run-log/bug-report JSON.
_SPEC = spec_for("sscfuzz")


def _tok_snap(stats: TokenUsage) -> tuple[int, int]:
    """Snapshot (input_tokens, output_tokens) values from a TokenUsage object."""
    return stats.input_tokens, stats.output_tokens


def build_bugs_payload(
    bugs: list[dict],
    run_log: dict,
    *,
    method: str,
    contract: str,
) -> dict:
    """Build the per-run bugs.json payload — mirrors run_log shape but bug-only.

    Schema:
      {
        "summary": {
          "method":               str,    sscfuzz | rlfuzz | madfuzz
          "contract":             str
          "timestamp":            ISO-8601 UTC,
          "total_bugs":           int,
          "total_iterations":     int   (from run_log.summary)
          "bc_coverage_ratio":    float
          "total_bc_branches":    int
          "total_coverage_bc_branches": int
          "total_reward":         float
        },
        "bugs": [...]   the same entries already accumulated in found_bugs
      }
    """
    s = (run_log or {}).get("summary", {}) or {}
    return {
        "summary": {
            "method":                       method,
            "contract":                     contract,
            "timestamp":                    _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "total_bugs":                   len(bugs),
            "total_iterations":             s.get("total_iterations", 0),
            "bc_coverage_ratio":            s.get("bc_coverage_ratio", 0.0),
            "total_bc_branches":            s.get("total_bc_branches", 0),
            "total_coverage_bc_branches":   s.get("total_coverage_bc_branches", 0),
            "total_reward":                 s.get("total_reward", 0.0),
        },
        "bugs": bugs,
    }


def run_fuzzing_loop(
    config: FuzzerConfig,
    contract_source: str,
    contract_abi: list[dict],
    verbose: bool = False,
    debug: bool = False,
    pinned_strategy: str | None = None,
    backend_label: str | None = None,
    model_label: str | None = None,
) -> tuple[list[dict], dict]:
    """Core fuzzing loop. Returns (found_bugs, full_run_log)."""

    # ── Initialization ────────────────────────────────────────────────────────
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        for _noisy in ("httpcore", "httpx", "anthropic._base_client", "hpack"):
            logging.getLogger(_noisy).setLevel(logging.WARNING)
        console.print("[dim]Debug mode enabled — verbose logging active[/dim]")

    # ── Action table (RL Iter 6: hard resize 17 → active roster) ───────────────
    # The action space is now built from the ACTIVE roster only — one DQN output
    # per legal action, no dead masked heads. `_action_table[i] = (mode, name)`
    # decodes action index i: gen entries first (indices [0, _n_gen)), then mut
    # entries ([_n_gen, len)). `config.rl.action_dim` is synced from
    # `len(_action_table)` before the DQN is built (same pattern as state_dim), so
    # a gated roster narrows the head to match. Empty blocklist → the full 7 gen +
    # 10 mut = 17-entry table (the ablation is one empty tuple away).
    _disabled_names = set(getattr(config, "disabled_strategies", ()) or ())
    _active_gen = [n for n in GENERATION_STRATEGIES if n not in _disabled_names]
    _active_mut = [n for n in MUTATION_STRATEGIES if n not in _disabled_names]
    _action_table: list[tuple[str, str]] = (
        [("generate", g) for g in _active_gen]
        + [("mutate", m) for m in _active_mut]
    )
    _n_gen = len(_active_gen)   # table indices [0, _n_gen) = gen; [_n_gen, len) = mut
    # Iter-4 state gate: disabled GENERATION strategies lose their per-strategy
    # reward slot in the state vector (a dead input dim otherwise). Iter-5: the
    # ACTIVE mutation strategies get their own reward block too (see StateEncoder
    # `active_mut_mask`), so the DQN has a learnable value signal for its mut
    # actions instead of mis-crediting them onto the seed's gen slot.
    _active_gen_mask = [n not in _disabled_names for n in GENERATION_STRATEGIES]
    _active_mut_mask = [n not in _disabled_names for n in MUTATION_STRATEGIES]
    if _disabled_names:
        console.print(
            f"[dim]Gated roster: {len(_active_gen)} gen + {len(_active_mut)} mut "
            f"= {len(_action_table)} active actions "
            f"(disabled: {', '.join(sorted(_disabled_names))})[/dim]"
        )
    generator = LLMGenerator(config.llm, initial_balance_native=config.initial_balance_native)
    _fork_cfg = getattr(config, "fork", None)
    # Mode-aware address pool shared by the ε-greedy random branch, the LLM-exhausted
    # fallback (generator) and the ABI-level mutator's address-redirect targets.
    _mode = "fork" if _fork_cfg else "inline"
    _external_addrs = [
        e.get("address") for e in (getattr(config, "external", None) or []) if e.get("address")
    ]
    _address_pool = build_address_pool(_mode, _external_addrs)
    fuzzer = FoundryFuzzer(
        config.foundry_project,
        config.contract_name,
        abi=contract_abi,
        initial_balance_native=config.initial_balance_native,
        contract_source=contract_source,
        fork=_fork_cfg,
        constructor_args=getattr(config, "constructor_args", None),
        constructor_value=getattr(config, "constructor_value", None),
        pre_deploy=getattr(config, "pre_deploy", None),
        setup_calls=getattr(config, "setup_calls", None),
        external=getattr(config, "external", None),
        setup_template=getattr(config, "setup_template", None),
    )
    # Hand the declared external contracts to the LLM client so the prompt lists
    # the callable non-target contracts and the GBNF grammar legalizes their
    # <var>.<method> heads + $ret chaining. No-op when external is empty.
    generator.set_external(getattr(config, "external", None))
    # Mode-aware address pool for the generator's LLM-exhausted random fallback.
    generator.set_address_pool(_address_pool)
    # Share generator's _LLMClient so generator and mutator see the same run history
    mutator = LLMMutator(
        config.rl, abi=contract_abi,
        initial_balance_native=config.initial_balance_native,
        shared_llm=generator._llm, address_pool=_address_pool,
    )

    found_bugs: list[dict] = []
    run_records: list[dict] = []
    # Iteration at which each rewarded exploit path was first banked — index k
    # mirrors FoundryFuzzer._rewarded_exploit_paths[k], so a later duplicate's
    # `bug_path_dup_of` maps back to the iteration it copied.
    rewarded_exploit_iters: list[int] = []
    # RL Iter 7 C1 — per-strategy coverage seen-set (learning concern, owned here;
    # foundry's _seen_bc_branch_ids stays the authoritative honest-coverage set).
    # Keyed by the pick label (mutation_strategy if mutate else strategy). Each run
    # pays the two-tier per-strategy BASE for branches new to its own label's set,
    # then updates it → every strategy stays rewarded on its own frontier.
    seen_bc_by_strategy: dict[str, set] = {}
    total_reward = 0.0
    iteration = 0
    run_id = 0
    # RL Iter 7 C5 — round-robin warmup counter (persisted across a checkpoint).
    warmup_counter = 0
    random_inputs_used = 0   # count of iterations where ε-greedy bypassed the LLM
    llm_fallbacks_used = 0    # count of iterations where the LLM exhausted retries → random

    # The CLI passes pre-resolved labels (incl. llama-cpp model detection);
    # other callers (experiment runners) pass nothing → derive from config.llm.
    if backend_label is None:
        backend_label, model_label, _ = backend_labels(config.llm)
    console.print(render_start_panel(
        spec_for("sscfuzz"),
        contract=config.contract_name,
        iterations=config.max_iterations,
        backend_label=backend_label,
        model_label=model_label,
        approach=config.llm.approach,
        # Active-roster size (RL Iter 6). config.rl.action_dim isn't synced from the
        # table until the DQN is built below, so read the table length directly here.
        strategies=len(_action_table),
    ))

    if not fuzzer.compile():
        console.print("[red]Compilation failed. Aborting.[/red]")
        return []

    # Build the state encoder now that fuzzer._bc_meta is populated — the
    # per-function heat-map needs branch-count ranking from the bytecode meta.
    # Prefer the AST (deterministic) over regex on source; fall back when
    # `forge build --ast` wasn't run (older artifacts, smoke tests).
    bc_meta = fuzzer._bc_meta
    if bc_meta is not None and bc_meta.ast is not None:
        features = ContractFeatures.from_ast(bc_meta.ast, contract_abi)
    else:
        features = ContractFeatures.from_source(contract_source, contract_abi)
    state_enc = StateEncoder(
        features, meta=bc_meta,
        active_gen_mask=_active_gen_mask, active_mut_mask=_active_mut_mask,
        # RL Iter 7 C3 — decaying per-active-strategy "proven bug-finder" trace, so
        # the policy can prefer a strategy that recently banked a novel exploit
        # AFTER the one-shot (path-gated) bug reward has evaporated. SScFuzz-only
        # flag; baselines/tests leave it off (state_dim unchanged).
        emit_bug_trace=config.rl.bug_trace,
        bug_trace_decay=config.rl.bug_trace_decay,
        # marginal_alpha — the per-arm reward-EWMA (`mrew`) recency weight, used by
        # the per-arm layout below (mrew/dry are per-arm tuple features).
        marginal_alpha=config.rl.marginal_alpha,
        # Per-arm layout (the shared-per-arm-head `sscfuzz`, factored_head): global
        # context block + one feature tuple per active arm, consumed by the factored
        # DQN head. Off for baselines / the bandit variant. See fuzzer/state.py.
        per_arm_layout=config.rl.factored_head,
        # emit_static (RL Iter 6, revived for the contextual bandit): feed the 5 F1
        # contract features into the global block. Off by default; sscfuzz_cb turns
        # it on so the LinUCB context can route per-strategy on contract identity.
        emit_static=config.rl.emit_static,
        # Context layout (the contextual-bandit `sscfuzz_cb`, LinUCB): emit ONLY the
        # global-context block (+F1) as the arm-independent context x. See
        # fuzzer/state.py + rl/contextual_bandit.py.
        context_layout=(config.rl.selector == "linucb"),
    )
    # RL Iter 7 C5 — round-robin warmup measured in ROUNDS (full roster cycles):
    # warmup_iters = warmup_rounds × active-roster size (n rounds × m strategies), so
    # `warmup_rounds` is the number of complete round-robin passes over the roster.
    # Bounded by max_iterations so a tiny run is never entirely warmup.
    effective_warmup = min(
        int(getattr(config, "warmup_rounds", 0) or 0) * len(_action_table),
        config.max_iterations,
    )

    # Build the DQN now the encoder width is known — the state gate (Iter 4) makes
    # state_dim depend on how many gen strategies survive `disabled_strategies`, so
    # sync RLConfig.state_dim from the encoder INSTANCE (not the class default)
    # before constructing the network so a gated roster narrows the input to match.
    config.rl.state_dim = state_enc.state_dim
    # Sync the action head to the active roster (RL Iter 6 hard resize) — same
    # instance-driven pattern as state_dim, so the DQN has exactly one output per
    # legal action (no dead masked heads). Empty blocklist → 17.
    config.rl.action_dim = len(_action_table)
    # Sync the factored head's structural params (n_global / arm_feat) from the
    # encoder instance too, so the network reshapes the per-arm state correctly:
    # n_global + action_dim·arm_feat must equal state_dim (asserted in DQNNetwork).
    if config.rl.factored_head:
        config.rl.n_global = state_enc.n_global
        config.rl.arm_feat = state_enc.arm_feat
    # Selector factory (Option C): "bandit" → BanditController (sscfuzz_esb),
    # else the RLController — the factored shared-per-arm-head DQN for `sscfuzz`
    # (factored_head), the flat dueling DQN for the baselines. config.rl.state_dim /
    # action_dim / n_global / arm_feat are synced above so the controller sizes to
    # the gated roster. Polymorphic surface below is identical either way.
    rl = make_controller(config.rl)

    # ── Cross-contract warm-start (DQN pretraining) ───────────────────────────
    # If a pretrained model was handed in, load it BEFORE any same-contract resume
    # checkpoint (below) so a crash-resume still wins over the transferred weights.
    # Only net-bearing selectors (RLController) expose .load; the bandit ignores it.
    _load_model = getattr(config, "load_model_path", None)
    if _load_model and hasattr(rl, "load"):
        if not os.path.exists(_load_model):
            console.print(f"[yellow]WARN: load_model_path {_load_model} not found — "
                          f"starting from a fresh DQN.[/yellow]")
        else:
            try:
                rl.load(_load_model)
                console.print(f"[green]Warm-started DQN from {_load_model} "
                              f"(eps={rl.epsilon:.3f}, step={rl.step_count})[/green]")
            except Exception as e:  # corrupt / arch-mismatched .pt must not kill the run
                console.print(f"[red]WARN: failed to load {_load_model} "
                              f"({type(e).__name__}: {e}) — continuing with a fresh DQN.[/red]")

    # Hand the AST + target name to the LLM client so `build_contract_context`
    # can extract just the target (+ in-file bases) when the full file would
    # bust the source-budget cap. Gen + mut share the same client via
    # `shared_llm`, so one call wires both. Silent no-op if AST is missing.
    if bc_meta is not None:
        generator.set_source_context(bc_meta.ast, config.contract_name)

    # ── Iteration-level checkpoint restore ────────────────────────────────────
    # The runner sets config.checkpoint_path/config.checkpoint_every so a very-long
    # run interrupted mid-contract resumes from the last flush (≤ checkpoint_every
    # iters of rework) instead of restarting at 0. All components are constructed
    # above; restore their evolving state + the loop counters here, before the loop.
    _ckpt_path = getattr(config, "checkpoint_path", None)
    _ckpt_every = int(getattr(config, "checkpoint_every", 0) or 0)
    _records_path = _ckpt.records_path(_ckpt_path) if (_ckpt_path and _ckpt_every > 0) else None
    if _ckpt_path and _ckpt_every > 0:
        _ck = _ckpt.load(_ckpt_path)
        if _ck is not None:
            iteration = _ck["iteration"]
            run_id = _ck["run_id"]
            total_reward = _ck["total_reward"]
            # run_records live in the sidecar JSONL (not the checkpoint blob), read
            # back truncated to the checkpoint's completed-iter count.
            run_records = _ckpt.load_records(_records_path, iteration)
            found_bugs = _ck["found_bugs"]
            rewarded_exploit_iters = _ck["rewarded_exploit_iters"]
            # RL Iter 7: restore per-strategy coverage sets + warmup counter (older
            # checkpoints predate these — default to empty/0).
            seen_bc_by_strategy = {
                k: set(v) for k, v in (_ck.get("seen_bc_by_strategy") or {}).items()
            }
            warmup_counter = _ck.get("warmup_counter", 0)
            random_inputs_used = _ck["random_inputs_used"]
            llm_fallbacks_used = _ck["llm_fallbacks_used"]
            rl.load_state_dict(_ck["rl"])
            fuzzer.restore_checkpoint_state(_ck["fuzzer"])
            state_enc.restore_checkpoint_state(_ck["state_enc"])
            mutator.restore_checkpoint_state(_ck["mutator"])
            generator._llm.restore_checkpoint_state(_ck["llm"])
            _ckpt.restore_rng(_ck.get("rng"))
            console.print(
                f"[green]▶ Resumed from checkpoint at iteration {iteration}"
                f"/{config.max_iterations}[/green]"
            )

    stats_table = Table(title="Live Stats", show_header=True, expand=False)
    stats_table.add_column("Iter", style="cyan")
    stats_table.add_column("Mode:Strategy", style="green")
    stats_table.add_column("Reward", style="yellow")
    stats_table.add_column("Coverage", style="blue")
    stats_table.add_column("ε", style="dim")
    stats_table.add_column("Corpus", style="magenta")
    stats_table.add_column("Bugs", style="red bold")

    # ── Main Loop ─────────────────────────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=not debug,  # in debug mode keep lines visible
        console=console,
    ) as progress:
        task = progress.add_task("Fuzzing...", total=config.max_iterations, completed=iteration)

        # Corpus capacity (Group A ∪ Group B upper bound) → maturity denominator.
        _corpus_cap = max(1, config.rl.corpus_top_coverage + config.rl.corpus_top_reward)

        while iteration < config.max_iterations:
            # Feed corpus maturity (fill fraction) into the state so the DQN can
            # learn the generation→mutation timing (RL Iter 3 §3A).
            state_enc.set_corpus_maturity(len(mutator) / _corpus_cap)
            # Feed the corpus-seed value stats (RL Iter 6) — mean/max seed reward,
            # clamped to ≥0 so lean reward=0 coverers don't drag the mean negative.
            # Answers "are the seeds worth mutating?" (a mature-but-worthless corpus
            # should still favor generation). Normalization happens in the setter.
            _seed_rewards = [max(0.0, e.reward) for e in getattr(mutator, "_corpus", [])]
            if _seed_rewards:
                state_enc.set_seed_pool(
                    sum(_seed_rewards) / len(_seed_rewards), max(_seed_rewards)
                )
            else:
                state_enc.set_seed_pool(0.0, 0.0)
            state = state_enc.encode()

            # ── Action selection (RL Iter 6 action table) ─────────────────────
            # `_action_table[i] = (mode, name)`: table indices [0, _n_gen) =
            # generate with an active gen strategy; [_n_gen, len) = mutate with an
            # active mut strategy. Mask the mut tail until the corpus has enough
            # seeds; there is no blocklist mask any more (disabled strategies are
            # simply absent from the table).
            if pinned_strategy is not None:
                strategy = pinned_strategy
                mode = "generate"
                mutation_strategy = None
                # Store slot for the (unused-in-pin-mode) learner; 0 if the pinned
                # strategy is gated out of the active table.
                action_idx = (
                    _action_table.index(("generate", pinned_strategy))
                    if ("generate", pinned_strategy) in _action_table else 0
                )
            else:
                corpus_ready = len(mutator) >= config.rl.mutation_min_corpus_size
                if corpus_ready:
                    valid_actions = list(range(len(_action_table)))
                else:
                    valid_actions = list(range(_n_gen))  # gen only
                # RL Iter 7 C5 — round-robin warmup: for the first `effective_warmup`
                # rounds cycle the roster (DQN idle for SELECTION but still storing +
                # training on these transitions), evenly seeding each strategy's
                # per-strategy coverage set + the corpus. The two-tier global bonus is
                # suppressed throughout (in_warmup below) so the easy sweep crowns no
                # lottery winner. Then the DQN takes over selection.
                if iteration < effective_warmup:
                    action_idx = valid_actions[warmup_counter % len(valid_actions)]
                    warmup_counter += 1
                    rl.last_q_chosen = None
                else:
                    action_idx = rl.select_strategy(state, valid_actions=valid_actions)
                mode, name = _action_table[action_idx]
                if mode == "mutate":
                    mutation_strategy = name
                    strategy = GENERATION_STRATEGIES[0]  # placeholder; overwritten from seed below
                else:
                    mutation_strategy = None
                    strategy = name

            strategy_idx = GENERATION_STRATEGIES.index(strategy)

            progress.update(
                task,
                description=f"[{iteration + 1}/{config.max_iterations}] "
                f"{mode}:{mutation_strategy if mode == 'mutate' else strategy}",
            )

            if debug:
                corpus_status = (
                    f"corpus={len(mutator)}"
                    if len(mutator) >= config.rl.mutation_min_corpus_size
                    else f"corpus={len(mutator)} [dim](need {config.rl.mutation_min_corpus_size} for mut)[/dim]"
                )
                if mode == "mutate":
                    console.print(
                        f"[dim]iter={iteration} mode=[magenta]{mode}[/magenta] "
                        f"mutation_strategy=[yellow]{mutation_strategy}[/yellow] "
                        f"{corpus_status} ε={rl.epsilon:.3f}[/dim]"
                    )
                else:
                    console.print(
                        f"[dim]iter={iteration} mode=[magenta]{mode}[/magenta] "
                        f"strategy=[cyan]{strategy}[/cyan] "
                        f"{corpus_status} ε={rl.epsilon:.3f}[/dim]"
                    )

            # ── Input generation (LLM for both modes) ────────────────────────
            seed_entry = None
            if mode == "mutate":
                seed_entry = mutator.sample_seed()  # any seed — mutation_strategy drives mutation
                if seed_entry is not None:
                    strategy = seed_entry.strategy  # use seed's strategy for context
                    strategy_idx = GENERATION_STRATEGIES.index(strategy)

            if debug:
                actor = mutator if seed_entry is not None else generator
                hist = actor.format_history_rich(mutation_strategy if mode == "mutate" else strategy)
                if hist and hist != "No runs yet.":
                    console.print("[dim]Recent history:[/dim]")
                    console.print(hist)

            # Snapshot token counts before the LLM call so we can compute per-call delta
            _ts = generator.token_stats
            tok_in_before, tok_out_before = _tok_snap(_ts)

            # ε-greedy random input injection — with probability eps_input, bypass
            # the LLM entirely and generate the iteration's input by uniform ABI
            # sampling. Closes the LLM's bias toward semantically-familiar function
            # names (which empirically skipped withdrawContractETH / borrow*ETH on
            # the DeFiHackLabs dataset). Schedule: geometric decay from start→end.
            eps_input = max(
                config.epsilon_random_input_end,
                config.epsilon_random_input_start * (config.epsilon_random_input_decay ** iteration),
            )
            use_random = random.random() < eps_input

            # Reset the shared fallback marker before each iteration. Gen/mut
            # set it to a reason string iff their LLM retry loop exhausts;
            # we read it below for the run-log `fallback` / `fallback_reason` fields.
            generator._llm.last_fallback_reason = None

            if use_random:
                random_inputs_used += 1
                # Tag the iteration as an intentional ε-greedy bypass — distinct
                # from the LLM-exhausted fallback path captured by gen/mut below.
                generator._llm.last_fallback_reason = (
                    f"epsilon_random_injection (eps={eps_input:.3f})"
                )
                if seed_entry is not None:
                    # Random mutation: ABI-level mutation_strategy on the seed, no LLM call.
                    fuzz_inputs = [mutator.mutate(seed_entry, mutation_strategy)]
                    child_step = {"mode": "mut", "name": f"random/{mutation_strategy}", "iter": iteration}
                    for fi in fuzz_inputs:
                        fi.lineage = list(seed_entry.fuzz_input.lineage) + [child_step]
                else:
                    # Random generation: uniform ABI sampling via llm.random_gen.
                    rand_input = random_fuzz_input(
                        contract_abi,
                        max_calls=config.llm.max_calls_per_item,
                        initial_balance_native=config.initial_balance_native,
                        address_pool=_address_pool,
                    )
                    fuzz_inputs = [FuzzInput.from_dict(rand_input)]
                    gen_step = {"mode": "gen", "name": f"random/{strategy}", "iter": iteration}
                    for fi in fuzz_inputs:
                        fi.lineage = [gen_step]
            elif seed_entry is not None:
                # Mutation mode: LLMMutator applies the mutation_strategy via LLM (fallback to ABI mutation)
                fuzz_inputs = mutator.llm_mutate(
                    seed_entry, mutation_strategy, contract_source, contract_abi,
                    n=config.llm.max_items_per_request, debug=debug,
                )
                # Stamp mutation lineage: parent's chain + this mut step.
                child_step = {"mode": "mut", "name": mutation_strategy, "iter": iteration}
                for fi in fuzz_inputs:
                    fi.lineage = list(seed_entry.fuzz_input.lineage) + [child_step]
            else:
                # Generation mode: LLMGenerator creates inputs from scratch
                fuzz_inputs = generator.generate(
                    contract_source, contract_abi, strategy,
                    n=config.llm.max_items_per_request, debug=debug,
                )
                # Stamp generation lineage: single-step chain rooted at this iteration.
                gen_step = {"mode": "gen", "name": strategy, "iter": iteration}
                for fi in fuzz_inputs:
                    fi.lineage = [gen_step]

            # Capture iteration-level fallback status — set by either the ε-random
            # branch above or by LLMGenerator.generate() / LLMMutator.llm_mutate() when
            # their retry loops exhaust. None on the LLM happy path.
            iter_fallback_reason: str | None = generator._llm.last_fallback_reason
            iter_fallback: bool = iter_fallback_reason is not None
            # Console "Fallback" metric counts only true LLM-retry exhaustion —
            # NOT the ε-greedy random injection (which sets an "epsilon_random_*"
            # reason and is tracked separately by random_inputs_used).
            if iter_fallback_reason and iter_fallback_reason.startswith("llm_exhausted"):
                llm_fallbacks_used += 1

            # Capture prompt/response and token delta for this LLM call
            llm_prompt = generator._llm.last_prompt
            llm_response = generator._llm.last_response
            _ts = generator.token_stats
            llm_tok_in = _ts.input_tokens - tok_in_before
            llm_tok_out = _ts.output_tokens - tok_out_before

            if debug:
                console.print(f"[dim]  LLM returned {len(fuzz_inputs)} input(s)[/dim]")

            # ── Execute each input ────────────────────────────────────────────
            for i, fuzz_input in enumerate(fuzz_inputs):
                if debug:
                    console.print(
                        f"[dim]  [{i+1}/{len(fuzz_inputs)}] "
                        f"{fuzz_input.description or fuzz_input.calls}[/dim]"
                    )

                _input_t0 = time.perf_counter()
                result = fuzzer.run_input(fuzz_input, strategy=strategy, debug=debug)
                seed_branches = seed_entry.bc_branches_this_run if seed_entry is not None else None
                # Plateau length BEFORE this iteration's update() — drives the
                # action-agnostic un-stick multiplier (RL Iter 6). Read here, since
                # state_enc.update() below mutates _stuck_counter.
                _stuck_before = state_enc._stuck_counter
                # RL Iter 7 C1 — per-strategy coverage base: branches new to THIS
                # pick label's own history (anti-starvation). Label = the action
                # (mutation_strategy for mut, else the gen strategy). Update the set
                # AFTER measuring per_strat_new so this run pays for its own frontier.
                _run_label = mutation_strategy if mode == "mutate" else strategy
                _label_seen = seen_bc_by_strategy.setdefault(_run_label, set())
                _per_strat_new = len(result.bc_branches_this_run - _label_seen)
                _label_seen |= result.bc_branches_this_run
                # Warmup suppresses the two-tier GLOBAL bonus (belt-and-suspenders
                # with the plateau gate) so the easy early sweep crowns no winner.
                _in_warmup = pinned_strategy is None and iteration < effective_warmup
                reward = compute_reward(
                    result, strategy=strategy, seed_branches=seed_branches, mode=mode,
                    stuck_before=_stuck_before,
                    unstick_lambda=config.rl.unstick_lambda,
                    unstick_min=config.rl.unstick_min,
                    unstick_scale=config.rl.unstick_scale,
                    two_tier=config.rl.two_tier_cov,
                    per_strat_new=_per_strat_new,
                    in_warmup=_in_warmup,
                    cov_ps_rate=config.rl.cov_ps_rate,
                    cov_global_rate=config.rl.cov_global_rate,
                    bug_scale=config.rl.bug_scale,
                )
                total_reward += reward

                if debug:
                    reason_str = result.raw_reason or "null"
                    console.print(
                        f"    → status={result.forge_status} | reason={reason_str} "
                        f"| gas={result.gas_used} | reward={reward:+.2f} "
                        f"| cov={result.coverage:.2%}"
                    )

                next_state = state_enc.encode()
                # In mutation mode credit the MUT slot (full MUTATION_STRATEGIES
                # index of the chosen mut strategy), not the seed's gen strategy_idx
                # (RL Iter 5 — fixes the mis-attribution). Derived from the strategy
                # name because action_idx is now a compact action-table index.
                _mut_idx = (
                    MUTATION_STRATEGIES.index(mutation_strategy) if mode == "mutate" else None
                )
                # RL Iter 7 C3 — feed the bank event to the decaying bug-success
                # trace: a novel exploit path (new_exploit_path==1) bumps THIS
                # action's slot (routed via mut_idx / strategy_idx like the reward),
                # giving the policy a durable, fading foothold on a proven bug-finder
                # after the one-shot bug reward evaporates.
                state_enc.update(
                    strategy_idx, result, reward, mut_idx=_mut_idx,
                    banked_exploit=(result.new_exploit_path == 1),
                )

                # Option C — outcome hook for the selector. No-op for the DQN
                # (RLController); BanditController (sscfuzz-esb) folds it into its
                # per-arm EWMA / dry / pin / cooldown bookkeeping. Called EVERY iter
                # incl. warmup (action_idx is set round-robin during warmup), so the
                # bandit can pin a quick-win bug from the very first rounds.
                rl.observe_outcome(
                    action_idx, reward,
                    found_new=result.new_bc_branches > 0,
                    banked=(result.new_exploit_path == 1),
                )

                rl.store(state, action_idx, reward, next_state, done=False)
                rl.train_step()

                # Both actors share history — one record_run call suffices
                run_label = mutation_strategy if mode == "mutate" else strategy
                generator.record_run(
                    fuzz_input, reward, result.forge_status, result.raw_reason or "",
                    result.new_bc_branches, result.decoded_logs,
                    strategy=run_label, mode=mode, fallback=iter_fallback,
                )

                # Admit every run unconditionally — Group A/B curation inside add()
                # decides what survives. No reward pre-filter: a reward=0 run can be
                # the *leanest* coverer of an existing branch (Group A wants it), and
                # a re-discovered exploit scores ~0 under the path gate yet must still
                # reach Group B as a lean witness.
                mutator.add(CorpusEntry(
                    fuzz_input=fuzz_input,
                    reward=reward,
                    strategy=strategy,
                    bc_branches_this_run=result.bc_branches_this_run,
                    iteration=iteration,
                    bug_signal_found=result.bug_signal_found,
                    # RL Iter 7 C6 — carry the tier so Group B (mutation seeds) can
                    # keep only WEAK-signal (heuristic) near-misses and exclude
                    # already-banked high-signal exploits (path-gated → no mutation value).
                    high_bug_signal_found=result.high_bug_signal_found,
                ))
                if debug:
                    console.print(
                        f"[dim]    → [magenta]corpus+[/magenta] reward={reward:+.2f} "
                        f"corpus_size={len(mutator)}[/dim]"
                    )

                # Build detailed run record (tokens attributed to first input in batch)
                fuzzing_output = build_fuzzing_output(reward, result)
                _rec = build_run_record(
                    _SPEC,
                    run_id=run_id,
                    iteration=iteration,
                    cum_reward=total_reward,
                    cum_unique_bc_branches=fuzzer.unique_bc_branches,
                    # +1 for this iteration's bug (found_bugs is appended below).
                    cum_bugs=len(found_bugs) + (1 if result.bug_signal_found else 0),
                    wall_ms=(time.perf_counter() - _input_t0) * 1000.0,
                    epsilon=rl.epsilon,
                    td_loss=rl.last_loss,
                    q_chosen=rl.last_q_chosen,
                    mode=mode,
                    strategy=strategy,
                    mutation_strategy=mutation_strategy,
                    fallback=iter_fallback,
                    fallback_reason=iter_fallback_reason,
                    lineage_signature=fuzz_input.signature,
                    lineage_depth=fuzz_input.depth,
                    llm_prompt=llm_prompt if i == 0 else "",
                    llm_response=llm_response if i == 0 else "",
                    fuzz_input=fuzz_input.to_dict(),
                    fuzzing_output=fuzzing_output,
                    tokens={
                        "input_tokens": llm_tok_in if i == 0 else 0,
                        "output_tokens": llm_tok_out if i == 0 else 0,
                        "total_tokens": (llm_tok_in + llm_tok_out) if i == 0 else 0,
                    },
                )
                run_records.append(_rec)
                if _records_path is not None:
                    _ckpt.append_record(_records_path, _rec)
                run_id += 1

                if result.bug_signal_found:
                    bug = build_bug_record(
                        _SPEC,
                        iteration=iteration,
                        mode=mode,
                        strategy=strategy,
                        mutation_strategy=mutation_strategy,
                        lineage_signature=fuzz_input.signature,
                        lineage_depth=fuzz_input.depth,
                        bug_type=result.bug_type,
                        fuzz_input=fuzz_input.to_dict(),
                        revert_reason=result.revert_reason,
                        trace=result.trace,
                    )
                    found_bugs.append(bug)
                    mode_detail = f"{mode}:{mutation_strategy}" if mode == "mutate" and mutation_strategy else mode
                    console.print(
                        f"\n[red bold]BUG FOUND[/red bold] at iter {iteration}: "
                        f"{result.bug_type} via [green]{strategy}[/green] "
                        f"([magenta]{mode_detail}[/magenta])\n"
                        f"[dim]  chain: {fuzz_input.signature}[/dim]"
                    )
                    if result.new_exploit_path == 1:
                        rewarded_exploit_iters.append(iteration)
                        if debug:
                            _tier_score = (
                                _HIGH_SIGNAL_SCORE if result.high_bug_signal_found
                                else _HEURISTIC_SIGNAL_SCORE
                            )
                            _tier_name = "high" if result.high_bug_signal_found else "heuristic"
                            console.print(
                                f"[dim]  DEBUG: novel exploit path ({_tier_name}) → "
                                f"[green]rewarded[/green] (+{_tier_score:.0f})[/dim]"
                            )
                    elif debug:
                        dup = result.bug_path_dup_of
                        dup_iter = (
                            rewarded_exploit_iters[dup]
                            if 0 <= dup < len(rewarded_exploit_iters) else "?"
                        )
                        console.print(
                            f"[dim]  DEBUG: exploit path too similar to the one from "
                            f"iter {dup_iter} → [yellow]not rewarded[/yellow][/dim]"
                        )

                if verbose:
                    stats_table.add_row(
                        str(iteration),
                        f"{mode[0].upper()}:{strategy}",
                        f"{reward:.2f}",
                        f"{result.coverage:.2%}",
                        f"{rl.epsilon:.3f}",
                        str(len(mutator)),
                        str(len(found_bugs)),
                    )

            iteration += 1
            progress.advance(task)

            # ── Periodic checkpoint flush (disk-only, every checkpoint_every) ──
            # Skip the final iteration: a completed run needs no resume point and
            # the runner clears the checkpoint on clean exit.
            if (_ckpt_every > 0 and _ckpt_path
                    and iteration < config.max_iterations
                    and iteration % _ckpt_every == 0):
                _ckpt.save(_ckpt_path, {
                    "iteration": iteration,
                    "run_id": run_id,
                    "total_reward": total_reward,
                    # run_records are NOT here — appended to the sidecar JSONL each
                    # iter (see checkpoint.append_record) to keep this blob small.
                    "found_bugs": found_bugs,
                    "rewarded_exploit_iters": rewarded_exploit_iters,
                    "seen_bc_by_strategy": {k: set(v) for k, v in seen_bc_by_strategy.items()},
                    "warmup_counter": warmup_counter,
                    "random_inputs_used": random_inputs_used,
                    "llm_fallbacks_used": llm_fallbacks_used,
                    "rl": rl.state_dict(),
                    "fuzzer": fuzzer.checkpoint_state(),
                    "state_enc": state_enc.checkpoint_state(),
                    "mutator": mutator.checkpoint_state(),
                    "llm": generator._llm.checkpoint_state(),
                    "rng": _ckpt.rng_state(),
                })

            if iteration % 10 == 0:
                cov = fuzzer.measure_coverage()
                if cov.bc_branches_total > 0:
                    console.print(
                        f"[blue]Coverage[/blue] iter={iteration}: "
                        f"{cov.bc_branches_hit}/{cov.bc_branches_total} "
                        f"([bold]{cov.bc_ratio:.1%}[/bold])"
                    )

    # ── Final keep-checkpoint (clean completion only) ─────────────────────────
    # Only reached when the loop ran to completion (a KeyboardInterrupt/crash
    # propagates out above, leaving the last PERIODIC flush for crash recovery).
    # Writes ONE complete checkpoint at the true last iteration (`iteration` ==
    # max_iterations here, e.g. 110 — not the last every-N flush at 100) so a later
    # higher-budget run continues from the real end. Not cleared on completion.
    if _ckpt_every > 0 and _ckpt_path and getattr(config, "keep_checkpoint", False):
        _ckpt.save(_ckpt_path, {
            "iteration": iteration,
            "run_id": run_id,
            "total_reward": total_reward,
            "found_bugs": found_bugs,
            "rewarded_exploit_iters": rewarded_exploit_iters,
            "seen_bc_by_strategy": {k: set(v) for k, v in seen_bc_by_strategy.items()},
            "warmup_counter": warmup_counter,
            "random_inputs_used": random_inputs_used,
            "llm_fallbacks_used": llm_fallbacks_used,
            "rl": rl.state_dict(),
            "fuzzer": fuzzer.checkpoint_state(),
            "state_enc": state_enc.checkpoint_state(),
            "mutator": mutator.checkpoint_state(),
            "llm": generator._llm.checkpoint_state(),
            "rng": _ckpt.rng_state(),
        })
        console.print(
            f"[dim]✔ kept final checkpoint at iteration {iteration} "
            f"(re-run with a higher --iterations to continue)[/dim]"
        )

    # ── Summary ───────────────────────────────────────────────────────────────
    cov = fuzzer.measure_coverage()
    # LLMGenerator and mutator share the same _LLMClient, so gen_tok covers both
    gen_tok = generator.token_stats
    total_in = gen_tok.input_tokens
    total_out = gen_tok.output_tokens
    console.print(render_done_panel(
        spec_for("sscfuzz"),
        total_reward=total_reward,
        cov=cov,
        corpus_size=len(mutator),
        bugs_found=len(found_bugs),
        fallback_used=llm_fallbacks_used,
        fallback_total=iteration,
        tokens_in=total_in,
        tokens_out=total_out,
    ))

    if verbose:
        console.print(stats_table)

    full_log = {
        "summary": build_run_summary(
            _SPEC,
            cov=cov,
            run_records=run_records,
            total_reward=total_reward,
            total_iterations=iteration,
            total_bugs=len(found_bugs),
            tokens_in=total_in,
            tokens_out=total_out,
            llm_fallback_count=llm_fallbacks_used,
            random_inputs_used=random_inputs_used,
            backend_label=backend_label,
            model_label=model_label,
            approach=config.llm.approach,
            corpus_size=len(mutator),
        ),
        "iterations": run_records,
        "bugs": found_bugs,
    }

    # ── Persist the trained model for cross-contract reuse ────────────────────
    # On clean completion, save just the model (net+optimizer+ε+step) so a later
    # run can warm-start from it. Chain load+save on one path to pretrain over a
    # contract sequence. Net-less selectors (bandit) have no .save → skipped.
    _save_model = getattr(config, "save_model_path", None)
    if _save_model and hasattr(rl, "save"):
        try:
            # Atomic write: save to a sibling temp then rename, so a process killed
            # mid-save can't corrupt a chained model.pt and poison the next warm-start.
            _tmp = f"{_save_model}.tmp"
            _dir = os.path.dirname(_save_model)
            if _dir:
                os.makedirs(_dir, exist_ok=True)
            rl.save(_tmp)
            os.replace(_tmp, _save_model)
            console.print(f"[green]Saved trained DQN -> {_save_model} "
                          f"(eps={rl.epsilon:.3f}, step={rl.step_count})[/green]")
        except Exception as e:  # a save failure shouldn't discard the completed run
            console.print(f"[red]WARN: failed to save model to {_save_model} "
                          f"({type(e).__name__}: {e})[/red]")

    return found_bugs, full_log
