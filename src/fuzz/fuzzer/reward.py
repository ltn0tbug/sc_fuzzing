"""Reward function for the fuzzing RL loop — balance-gain focused.

Signals (only three things matter):
  baseline   : 0.0 constant (a no-op run is negative, prevents reward hacking)
  coverage   : up to +40 total, normalized by bc_branches_total
  novelty    : up to +10 total — **mutation only**, measured against the seed
  BUG_SIGNAL : tiered, iff the exploit PATH is novel (else 0; see gate below).

**RL Iter 7 two-tier coverage (SScFuzz-only, two_tier=True).** The single shared
coverage term above is the LEGACY / baseline path (still the default — RLFuzz /
MADFuzz / LLMFuzz keep it). SScFuzz's orchestrator passes two_tier=True to split
coverage into two tiers and drop the novelty term: (1) a small PER-STRATEGY base
paid every run for branches new to THAT strategy's own history (anti-starvation —
so a late-arriving vuln strategy is never zeroed on already-globally-seen branches,
the front-loaded-lottery failure that anti-selected it); (2) a larger GLOBAL-new
bonus, GATED by (past the round-robin warmup AND stuck_before≥unstick_min) and
amplified by the plateau multiplier, so only hard-won post-plateau global-frontier
advances pay and the easy early sweep crowns no lottery winner. See compute_reward.
               A run with a tier=high signal (attacker_profit / target_loss — a
               proved net impact) pays _HIGH_SIGNAL_SCORE; a novel path with only
               tier=heuristic signals (a suspicious balance move that may be a fair
               trade) pays the smaller _HEURISTIC_SIGNAL_SCORE. PER RUN and MAX,
               never a sum — a run that trips several BUG_SIGNAL lines still pays a
               single tier score (the max tier present), never score × signals.

An action-AGNOSTIC **un-stick multiplier** (RL Iter 6) scales the progress terms
(coverage + novelty, never the bug score) when they fire after a coverage plateau:
breaking a long stall pays more than routine early coverage, so E[reward|action]
stays differentiated late in a run once raw coverage flatlines (the failure mode
that collapsed softmax-over-Q into ≈ uniform selection). It rewards the OUTCOME
(un-sticking), not "mutate" by name — the policy learns mut-when-stalled from the
gen_stall / seed-pool state dims (state.py). OFF by default (unstick_lambda=0);
orchestrator threads RLConfig.unstick_* so baselines / non-RL callers are unchanged.

This is the discretized first step of a graded-amount reward: each parsed signal
carries an `amount` (wei of the chain numéraire) in `FuzzResult.bug_signals`; a
future refinement can scale the high term by the net-profit `amount` of the value
verdicts. For now the tier (high vs heuristic) IS the graduation — path-gated.

Coverage and novelty operate on **bytecode-level** branches —
(jumpi_pc, direction) pairs from the runtime bytecode, with no source-line
dedup and no dispatcher filter. This rewards exercising every distinct JUMPI
in the contract (deeper exploration than source-level branches, which collapse
compiler-generated overflow checks / modifier guards into single decisions).

**Why novelty is mut-only**: in generation mode, every "new" branch is already
credited once by cov_reward (against the cumulative `_seen_bc_branch_ids`).
A second term over the same set is just a rate boost, not a different signal.
Mutation novelty measures something genuinely different: it compares against
this single corpus seed's branches, so it can fire even when no globally-new
branches are found — rewarding the child for exploring elsewhere than its parent.

**Bug reward is path-gated.** A BUG_SIGNAL run earns its tier score only the
first time its exploit *path* is seen; reruns of the same attack (padded or not)
score 0. The gate lives in `FoundryFuzzer._postprocess_result`, which stamps
`FuzzResult.new_exploit_path` (1/0) by comparing the run's `bc_branches_this_run`
against a session list of already-rewarded exploit paths (Jaccard<0.9 ⇒ distinct;
see fuzzer/paths.py). This mirrors the cumulative `_seen_bc_branch_ids` coverage
dedup, but for whole attack paths — and closes the bug-farming hole (research.md
Q6). It is global, NOT per-bug-class: bug "type" is meaningless for selection.

Note: bug *detection* is independent of reward — `FuzzResult.bug_signal_found` is set
to True by `_postprocess_result` iff a `BUG_SIGNAL:` line appears, regardless of
the gate. Reward is purely a search signal for the RL controller.
"""

from .foundry import FuzzResult

_BASELINE = 0.0
_COV_MAX = 40.0
_NOVELTY_MAX = 10.0
_HIGH_SIGNAL_SCORE = 50.0       # tier=high: a confirmed net impact (attacker_profit / target_loss)
_HEURISTIC_SIGNAL_SCORE = 5.0   # tier=heuristic: a suspicious balance move past threshold
_BUG_SIGNAL_SCORE = _HIGH_SIGNAL_SCORE  # legacy alias (kept for external imports)


def _cov_reward(result: FuzzResult) -> float:
    """Up to _COV_MAX points; each new bc-branch = _COV_MAX / bc_branches_total."""
    if result.new_bc_branches == 0:
        return 0.0
    if result.bc_branches_total > 0:
        return (_COV_MAX / result.bc_branches_total) * result.new_bc_branches
    return 0.1 * result.new_bc_branches  # fallback when total unknown


def _bug_signal_score(result: FuzzResult) -> float:
    """Tiered, path-gated bug score — the MAX tier present, never the sum.

    `result.new_exploit_path` (0/1) is set by the foundry path-novelty gate; a
    padded rerun of an already-rewarded exploit has new_exploit_path=0 and earns
    nothing here (the gate is unchanged). On a NOVEL path, the score is graduated by
    signal tier: a tier=high signal (attacker_profit / target_loss — a proved net
    impact) pays _HIGH_SIGNAL_SCORE; a novel path with only tier=heuristic signals
    (a suspicious balance move that might be a fair trade) pays the smaller
    _HEURISTIC_SIGNAL_SCORE. It is a per-RUN score, NOT a count of BUG_SIGNAL lines —
    a run that trips attacker_profit + attacker_gained + target_drained at once still
    scores a single _HIGH_SIGNAL_SCORE (the max tier), never score × signals.
    """
    if not result.new_exploit_path:
        return 0.0
    tiers = {s.get("tier") for s in result.bug_signals}
    return _HIGH_SIGNAL_SCORE if "high" in tiers else _HEURISTIC_SIGNAL_SCORE


def _novelty(result: FuzzResult, mode: str, seed_branches: frozenset | None) -> float:
    """Mutation-only divergence bonus, capped at _NOVELTY_MAX.

    Measures how many bc-branches the child found that the seed didn't —
    a different signal from `_cov_reward`, which compares against the
    cumulative global seen-set. This term can fire even when no globally-new
    branches were discovered (the child re-hit known branches the seed missed).

    Rate is size-normalized to match `_cov_reward`'s shape: each seed-novel
    branch is worth `_NOVELTY_MAX / bc_branches_total`, so a child that fully
    diverges from its seed saturates the cap regardless of contract size.
    """
    if mode != "mutate" or seed_branches is None:
        return 0.0
    novel = len(result.bc_branches_this_run - seed_branches)
    if novel == 0:
        return 0.0
    if result.bc_branches_total > 0:
        return min(_NOVELTY_MAX, (_NOVELTY_MAX / result.bc_branches_total) * novel)
    return min(_NOVELTY_MAX, 0.1 * novel)  # fallback when total unknown


def _global_new_bonus(
    result: FuzzResult, rate: float, stuck_before: int,
    unstick_lambda: float, unstick_min: int, unstick_scale: float,
) -> float:
    """Two-tier tier 2 (RL Iter 7): the GLOBAL-frontier advance bonus.

    Pays `rate / bc_branches_total` per branch new to the GLOBAL seen-set
    (`result.new_bc_branches`), amplified by the plateau multiplier — but ONLY
    when the caller has cleared the gate (past warmup AND stuck_before≥unstick_min;
    see compute_reward). Breaking the global frontier after a long stall is the
    progress worth crediting a strategy for; the caller decides when the gate opens.
    """
    if result.new_bc_branches <= 0:
        return 0.0
    if result.bc_branches_total > 0:
        bonus = (rate / result.bc_branches_total) * result.new_bc_branches
    else:
        bonus = 0.1 * result.new_bc_branches
    if unstick_lambda > 0.0 and stuck_before >= unstick_min:
        bonus *= 1.0 + unstick_lambda * min(
            stuck_before / max(unstick_scale, 1e-9), 1.0
        )
    return bonus


def _per_strategy_base(per_strat_new: int, bc_branches_total: int, rate: float) -> float:
    """Two-tier tier 1 (RL Iter 7): the per-strategy anti-starvation base.

    Pays `rate / bc_branches_total` per branch new to THIS strategy's own history
    (`per_strat_new`, computed by orchestrator from `seen_bc_by_strategy`). Always
    paid — so a late-arriving vuln strategy is never zeroed on already-globally-seen
    branches (the front-loaded-lottery failure) and stays a live selection option.
    """
    if per_strat_new <= 0:
        return 0.0
    if bc_branches_total > 0:
        return (rate / bc_branches_total) * per_strat_new
    return 0.1 * per_strat_new


def compute_reward(
    result: FuzzResult,
    strategy: str = "",
    seed_branches: frozenset | None = None,
    mode: str = "generate",
    stuck_before: int = 0,
    unstick_lambda: float = 0.0,
    unstick_min: int = 0,
    unstick_scale: float = 1.0,
    *,
    two_tier: bool = False,
    per_strat_new: int = 0,
    in_warmup: bool = False,
    cov_ps_rate: float = 8.0,
    cov_global_rate: float = _COV_MAX,
    bug_scale: float = 1.0,
) -> float:
    """Compute scalar reward from a fuzz result.

    Strategy is accepted for call-site compatibility but no longer changes the
    reward — BUG_SIGNAL is the only true-positive signal, and revert reasons
    in Solidity ≥0.8 typically mean the contract defended itself (not a bug).

    seed_branches  — frozenset of bc-branch IDs (jumpi_pc, direction) hit by
                     the corpus seed. Required for novelty; if None or in
                     generate mode, novelty term is zero. **Legacy path only.**
    mode           — "generate" or "mutate"; selects the novelty rate. **Legacy path.**

    ── Legacy / baseline path (two_tier=False, the DEFAULT) ───────────────────
    Unchanged: `progress = _cov_reward + _novelty`, scaled by the RL Iter 6
    action-agnostic un-stick multiplier when progress is made after a ≥unstick_min
    plateau, plus the path-gated bug score. RLFuzz / MADFuzz / LLMFuzz keep this
    path (they never pass two_tier=True), so the baseline ablation stays clean.

    ── Two-tier path (two_tier=True, SScFuzz-only, RL Iter 7) ─────────────────
    Replaces the single shared coverage term with two tiers (fixes the
    front-loaded coverage lottery that anti-selected the vuln strategy):
      base  = cov_ps_rate  * per_strat_new     / total   ← ALWAYS paid (anti-starvation)
      bonus = cov_global_rate * new_bc_branches / total   ← GATED + plateau-amplified
              paid only when (not in_warmup) AND stuck_before ≥ unstick_min, so the
              easy early sweep crowns no winner; only hard-won post-plateau
              global-frontier advances pay. `in_warmup`/`per_strat_new` come from
              orchestrator (which owns `seen_bc_by_strategy`). No `_novelty` term:
              per-strategy coverage subsumes it (novelty was "new vs one seed";
              per-strategy base is "new vs this strategy's whole history" — RL Iter
              7 C4). The bug score is common to both paths, scaled by `bug_scale`.
    """
    _ = strategy  # accepted for compatibility; no longer used
    bug = _bug_signal_score(result) * bug_scale

    if not two_tier:
        # Legacy / baseline path — unconditional coverage + mut novelty (unchanged).
        progress = _cov_reward(result) + _novelty(result, mode, seed_branches)
        if progress > 0.0 and unstick_lambda > 0.0 and stuck_before >= unstick_min:
            progress *= 1.0 + unstick_lambda * min(
                stuck_before / max(unstick_scale, 1e-9), 1.0
            )
        return _BASELINE + progress + bug

    # Two-tier path (SScFuzz): per-strategy base always paid; global bonus gated.
    base = _per_strategy_base(per_strat_new, result.bc_branches_total, cov_ps_rate)
    bonus = 0.0
    if not in_warmup and stuck_before >= unstick_min:
        bonus = _global_new_bonus(
            result, cov_global_rate, stuck_before,
            unstick_lambda, unstick_min, unstick_scale,
        )
    return _BASELINE + base + bonus + bug
