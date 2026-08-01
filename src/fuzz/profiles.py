"""Per-method default profiles — single place to change the defaults for sscfuzz / rlfuzz / madfuzz.

Each profile is a frozen dataclass that snapshots ALL knobs the method
consumes (RL hyperparameters + LLM config + input-ε for sscfuzz, RL only
for rlfuzz, RL + LLM for madfuzz). Runners call `materialize(mode=...)` to
get a ready-to-use FuzzerConfig / BaselineConfig with the mode overlay
applied on top of the method defaults.

Layering — who owns what:

  * fuzz.config (RLConfig / LLMConfig / FuzzerConfig)
      = dataclass *schema* — the field set every method shares.
  * fuzz.profiles (this file)
      = per-method *default values* — change here to affect one method
        globally without touching the schema or the runners.
  * experiment_run/profile.py
      = experiment-time *regime overlay* — picks "test" vs "long" vs
        "very_long" iteration budgets and the consistent ε / batch_size /
        target_sync adjustments that go with each regime.

Adding a new method (e.g. "myfuzz"):

  1. Add MYFUZZ_DEFAULTS here following the same pattern.
  2. Wire a runner that imports it: `myfuzz_defaults.materialize(mode='long')`.
  3. Done — no edits needed in fuzz.config or other methods' profiles.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Optional

from .config import FuzzerConfig, LLMConfig, RLConfig

# ── Regime → (RL/input-ε) overlay ─────────────────────────────────────────────
# See research.md §10 Q8 for the math. Each regime tunes batch_size +
# epsilon_decay + target_sync_every for the iteration budget so the DQN
# actually trains in the allotted time.

# `warmup` (RL Iter 7 C5, SScFuzz-only) is the number of round-robin ROUNDS (full
# cycles over the active roster) the orchestrator runs before handing selection to
# the DQN — so warmup_iters = warmup × active-roster size (e.g. 2 rounds × 9 = 18
# iters). During warmup the DQN is idle for selection but still learning, and the
# two-tier global bonus is suppressed, so the easy early coverage sweep crowns no
# lottery winner. orchestrator bounds warmup_iters by max_iterations. Only SScFuzz
# threads it (FuzzerConfig.warmup_rounds); the baseline BaselineConfig has no such
# field → warmup off for baselines.
_REGIMES: dict[str, dict[str, Any]] = {
    "test":      {"max_iter": 15,  "batch": 4,  "rl_decay": 0.85, "sync": 5,
                  "in_eps_start": 0.5, "in_eps_decay": 0.85, "warmup": 1},
    "medium":    {"max_iter": 50,  "batch": 8,  "rl_decay": 0.92, "sync": 10,
                  "in_eps_start": 0.4, "in_eps_decay": 0.92, "warmup": 1},
    "long":      {"max_iter": 100, "batch": 8,  "rl_decay": 0.95, "sync": 20,
                  "in_eps_start": 0.3, "in_eps_decay": 0.95, "warmup": 2},
    "very_long": {"max_iter": 500, "batch": 16, "rl_decay": 0.97, "sync": 50,
                  "in_eps_start": 0.2, "in_eps_decay": 0.97, "warmup": 2},
}


def _apply_regime(rl: RLConfig, mode: str) -> RLConfig:
    if mode not in _REGIMES:
        raise ValueError(f"unknown mode={mode!r}; valid: {sorted(_REGIMES)}")
    r = _REGIMES[mode]
    return replace(rl,
                   batch_size=r["batch"],
                   epsilon_decay=r["rl_decay"],
                   target_sync_every=r["sync"])


# ── SScFuzz profile ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SScFuzzDefaults:
    """SScFuzz = RL + LLM gen×mut hybrid + ε-greedy random input injection.

    Backs the **`sscfuzz_dqn`** registry method (the factored-DQN selector). NB: the
    bare `sscfuzz` method name is an ALIAS for `sscfuzz_esb` (the switching bandit) —
    see `experiment/run/registry.py::METHOD_ALIASES`. This profile is still the base
    class the esb / cb selector variants subclass (overriding only `rl`).

    Edit any field here to change SScFuzz's default behavior across every
    runner / experiment / test that materializes this profile.
    """
    # PER + the RL Iter 2 learner upgrades (dueling / double-DQN / reward
    # normalization) are on for SScFuzz only — the baselines keep the vanilla
    # RLConfig (all flags False) so the comparison stays a clean ablation and
    # RLFuzz / MADFuzz remain faithful vanilla-DQN reproductions.
    # RL Iter 7 adds two_tier_cov (two-tier coverage reward, C1/C4) + bug_trace
    # (decaying bug-success state trace, C3) — SScFuzz-only, baselines stay vanilla.
    # Selector rework (2026-07-10): SScFuzz now uses the FACTORED shared-per-arm-head
    # DQN (`factored_head`) over the StateEncoder per-arm layout — one shared sub-net
    # scores every arm from its own (avg, mrew, dry, bug_trace, is_mut) tuple + the
    # global context, pooling the "pick a rising / not-dried arm" rule across arms so
    # a barely-tried arm is scored immediately (attacks the RQ3a starvation). This
    # folds in the retired `sscfuzz_ms` recency/exhaustion signals (mrew/dry) as
    # per-arm tuple features. The `sscfuzz_esb` bandit variant is unchanged.
    rl: RLConfig = field(default_factory=lambda: RLConfig(
        use_per=True, dueling=True, double_dqn=True, normalize_rewards=True,
        softmax_exploration=True, n_step=3,
        two_tier_cov=True, bug_trace=True,
        selector="dqn", factored_head=True))
    llm: LLMConfig = field(default_factory=LLMConfig)
    initial_balance_native: int = 10
    epsilon_random_input_start: float = 0.3
    # RL Iter 7 C5 — hold the ε-random-INPUT floor into the late rounds (0.10→0.12)
    # for uniform-ABI input diversity that counters the 1.5B model's function-name
    # fixation; RL's softmax exploration already persists (the "dual random" late).
    epsilon_random_input_end:   float = 0.12
    epsilon_random_input_decay: float = 0.95
    # Gated-off strategies (RL Iter 1 prune): the 5 dead mutation strategies
    # (0.00 unbiased yield, 0 unique solves — each duplicates a gen strategy) +
    # boundary_values (its distinct numeric-boundary content is folded into
    # arithmetic_probe) + `arg_address` (generalized by `arg_shuffle`, which
    # rewrites an argument of ANY type — so arg_shuffle takes its active-roster
    # slot). `call_swap` is ACTIVE (kept in the roster by explicit decision rather
    # than held for the §3D measurement bar). RL Iter 7 C2 ALSO gates `exploration`:
    # it is pure breadth already supplied by the ε-random *input* injection + the
    # per-strategy coverage base, and was the DQN's mis-concentration magnet (top
    # gen pick on multiowned while access_control got 0). Active roster now 5 gen +
    # 4 mut (value_perturb, call_insert, arg_shuffle, call_swap) = 9. RL Iter 6 hard-
    # resizes action_dim to len(_action_table)=9; set to () for the full-17 ablation.
    disabled_strategies: tuple[str, ...] = (
        "arg_boundary", "caller_swap", "call_delete", "call_shuffle",
        "reentry_depth", "boundary_values", "arg_address", "exploration",
    )

    def materialize(self, *, mode: str = "long",
                    contract_name: str = "",
                    foundry_project: str = "",
                    fork: Optional[Any] = None,
                    llm_overrides: Optional[dict[str, Any]] = None,
                    ) -> FuzzerConfig:
        """Return a runnable FuzzerConfig with the mode-regime overlay applied."""
        r = _REGIMES[mode]
        llm_kwargs = dict(llm_overrides or {})
        llm = replace(self.llm, **llm_kwargs)
        return FuzzerConfig(
            max_iterations=r["max_iter"],
            contract_name=contract_name,
            foundry_project=foundry_project,
            initial_balance_native=self.initial_balance_native,
            rl=_apply_regime(self.rl, mode),
            llm=llm,
            fork=fork,
            epsilon_random_input_start=r["in_eps_start"],
            epsilon_random_input_end=self.epsilon_random_input_end,
            epsilon_random_input_decay=r["in_eps_decay"],
            disabled_strategies=self.disabled_strategies,
            # RL Iter 7 C5 — regime-scaled round-robin warmup (SScFuzz-only).
            warmup_rounds=r["warmup"],
        )


# ── SScFuzz selector variant (Option C) ───────────────────────────────────────
# The `sscfuzz_esb` SELECTOR ablation of SScFuzz: everything (two-tier reward,
# corpus, warmup, ε-random input, LLM roster + gate) is identical to `sscfuzz`;
# ONLY the strategy selector changes, so the comparison is a clean selector
# ablation. It subclasses SScFuzzDefaults and overrides only `rl`, inheriting its
# disabled_strategies / ε-input schedule / warmup / materialize. (The retired
# `sscfuzz_ms` DQN+marginal variant is now folded into `sscfuzz` itself — its
# recency/exhaustion signals became per-arm tuple features of the factored head.)


@dataclass(frozen=True)
class SScFuzzESBDefaults(SScFuzzDefaults):
    """SScFuzz-esb = Exhaustion-Switching Bandit selector (no neural net).

    Replaces the DQN with `BanditController` (rl/bandit.py) — the user's
    non-stationary-bandit hypothesis, coded: warmup-pin quick wins, exploit the
    best RECENT-payoff arm while it keeps finding branches, give up an arm after
    `bandit_giveup` unproductive picks. Keeps the two-tier coverage reward (so the
    per-arm payoff is anti-starvation-shaped like sscfuzz); the bug-trace STATE and
    the DQN-upgrade flags are irrelevant/off (no net is built).
    """
    rl: RLConfig = field(default_factory=lambda: RLConfig(
        selector="bandit", two_tier_cov=True, bug_trace=False,
        bandit_epsilon=0.15, bandit_ewma_alpha=0.5,
        bandit_giveup=5, bandit_cooldown=10))


# ── SScFuzz contextual-bandit variant (LinUCB) ────────────────────────────────
# The `sscfuzz_cb` SELECTOR ablation: everything (two-tier reward, corpus, warmup,
# ε-random input, LLM roster + gate) is identical to `sscfuzz`; ONLY the selector
# changes to a disjoint LinUCB contextual bandit (rl/contextual_bandit.py) over the
# StateEncoder CONTEXT layout. emit_static feeds the F1 contract features into the
# context so each arm's θ_a routes per-strategy on contract identity and transfers
# across contracts via --load-model/--save-model (the RQ3a §7.4(ii)′ answer, where
# the factored DQN collapsed to a contract-agnostic average). Subclasses
# SScFuzzDefaults, overriding only `rl`.


@dataclass(frozen=True)
class SScFuzzCBDefaults(SScFuzzDefaults):
    """SScFuzz-cb = disjoint LinUCB contextual-bandit selector (no neural net).

    Each arm has its own discounted linear model θ_a over the context (global block
    + F1 when emit_static). Keeps the two-tier coverage reward (so the per-arm payoff
    is anti-starvation-shaped like sscfuzz); the bug-trace STATE and the DQN-upgrade
    flags are irrelevant/off (no net is built).
    """
    rl: RLConfig = field(default_factory=lambda: RLConfig(
        selector="linucb", emit_static=True, two_tier_cov=True, bug_trace=False,
        linucb_alpha=1.0, linucb_lambda=1.0, linucb_discount=0.95))


# ── RLFuzz profile ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RLFuzzDefaults:
    """RLFuzz = group DQN + uniform random args (no LLM)."""
    rl: RLConfig = field(default_factory=RLConfig)
    initial_balance_native: int = 10
    max_calls_per_item: int = 12

    def materialize(self, *, mode: str = "long",
                    contract_name: str = "",
                    foundry_project: str = "",
                    fork: Optional[Any] = None,
                    ) -> "BaselineConfig":
        from .baselines.common.config import BaselineConfig
        return BaselineConfig(
            max_iterations=_REGIMES[mode]["max_iter"],
            contract_name=contract_name,
            foundry_project=foundry_project,
            initial_balance_native=self.initial_balance_native,
            max_calls_per_item=self.max_calls_per_item,
            rl=_apply_regime(self.rl, mode),
            fork=fork,
        )


# ── MADFuzz profile ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MADFuzzDefaults:
    """MADFuzz = 6-group DQN + per-type arg DQNs + one-shot LLM seed pool."""
    rl: RLConfig = field(default_factory=RLConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    initial_balance_native: int = 10
    max_calls_per_item: int = 12
    use_llm_seed: bool = True
    llm_pool_prob: float = 0.3
    # Max fuzz-input objects the seed-pool LLM call may return in a single
    # response. Set higher than LLMConfig.max_items_per_request (=1) because
    # MADFuzz's seed pool benefits from multi-item responses.
    max_items_per_request: int = 5

    def materialize(self, *, mode: str = "long",
                    contract_name: str = "",
                    foundry_project: str = "",
                    fork: Optional[Any] = None,
                    ) -> "BaselineConfig":
        from .baselines.common.config import BaselineConfig
        llm = replace(self.llm,
                      max_calls_per_item=self.max_calls_per_item,
                      max_items_per_request=self.max_items_per_request)
        return BaselineConfig(
            max_iterations=_REGIMES[mode]["max_iter"],
            contract_name=contract_name,
            foundry_project=foundry_project,
            initial_balance_native=self.initial_balance_native,
            max_calls_per_item=self.max_calls_per_item,
            rl=_apply_regime(self.rl, mode),
            llm=llm,
            fork=fork,
        )


# ── RandomFuzz profile ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RandomFuzzDefaults:
    """RandomFuzz = pure uniform random ABI sampling, no RL, no LLM."""
    initial_balance_native: int = 10
    max_calls_per_item: int = 12

    def materialize(self, *, mode: str = "long",
                    contract_name: str = "",
                    foundry_project: str = "",
                    fork: Optional[Any] = None,
                    ) -> "BaselineConfig":
        from .baselines.common.config import BaselineConfig
        return BaselineConfig(
            max_iterations=_REGIMES[mode]["max_iter"],
            contract_name=contract_name,
            foundry_project=foundry_project,
            initial_balance_native=self.initial_balance_native,
            max_calls_per_item=self.max_calls_per_item,
            fork=fork,
        )


# ── LLMFuzz profile ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LLMFuzzDefaults:
    """LLMFuzz = LLM-only (no RL) over the active generation+mutation roster.

    Each iteration a strategy is sampled UNIFORMLY from the active roster (both
    generation and mutation strategies, minus `disabled_strategies`) — the LLM is
    the only selector, no DQN — making LLMFuzz a clean RL-ablation of SScFuzz
    (identical action space + gate, uniform selection). A corpus feeds the
    mutation strategies. History is maintained so the model sees what has been
    tried; LLM failures fall back to random_fuzz_input.
    """
    llm: LLMConfig = field(default_factory=LLMConfig)
    initial_balance_native: int = 10
    max_calls_per_item: int = 12
    # Same gate as SScFuzz so LLMFuzz's active roster matches (5 gen + 4 mut = 9):
    # 5 dead mutations + boundary_values (folded into arithmetic_probe) + arg_address
    # (generalized by arg_shuffle) + exploration (RL Iter 7 C2 — pure breadth already
    # supplied by ε-random input; keep the ablation matched to SScFuzz). call_swap is active.
    disabled_strategies: tuple[str, ...] = (
        "arg_boundary", "caller_swap", "call_delete", "call_shuffle",
        "reentry_depth", "boundary_values", "arg_address", "exploration",
    )

    def materialize(self, *, mode: str = "long",
                    contract_name: str = "",
                    foundry_project: str = "",
                    fork: Optional[Any] = None,
                    llm_overrides: Optional[dict[str, Any]] = None,
                    ) -> "BaselineConfig":
        from .baselines.common.config import BaselineConfig
        llm_kwargs = dict(llm_overrides or {})
        llm = replace(self.llm, **llm_kwargs)
        return BaselineConfig(
            max_iterations=_REGIMES[mode]["max_iter"],
            contract_name=contract_name,
            foundry_project=foundry_project,
            initial_balance_native=self.initial_balance_native,
            max_calls_per_item=self.max_calls_per_item,
            llm=llm,
            fork=fork,
            disabled_strategies=self.disabled_strategies,
        )


# ── FinanceFuzz profile ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class FinanceFuzzDefaults:
    """FinanceFuzz competitor = evolutionary engine + financial-property oracle.

    No RL, no LLM. The regime `max_iter` is the total individual budget
    (generations × population); the runner derives `generations` from it. GA
    hyperparameters mirror the paper (§6.1): pc=0.9, pm=0.1, max length 20,
    population reset after 10 stale generations."""
    initial_balance_native: int = 10
    population: int = 12
    p_crossover: float = 0.9
    p_mutation: float = 0.1
    max_individual_length: int = 20
    stale_reset: int = 10
    equivalence_elite: int = 4

    def materialize(self, *, mode: str = "long",
                    contract_name: str = "",
                    foundry_project: str = "",
                    fork: Optional[Any] = None,
                    ) -> "BaselineConfig":
        from .baselines.common.config import BaselineConfig
        return BaselineConfig(
            max_iterations=_REGIMES[mode]["max_iter"],   # total individual budget
            contract_name=contract_name,
            foundry_project=foundry_project,
            initial_balance_native=self.initial_balance_native,
            max_calls_per_item=self.max_individual_length,
            fork=fork,
        )


# ── Singleton instances — import these from runners ───────────────────────────

sscfuzz_defaults    = SScFuzzDefaults()
sscfuzz_esb_defaults = SScFuzzESBDefaults()
sscfuzz_cb_defaults = SScFuzzCBDefaults()
rlfuzz_defaults     = RLFuzzDefaults()
madfuzz_defaults    = MADFuzzDefaults()
randomfuzz_defaults = RandomFuzzDefaults()
llmfuzz_defaults    = LLMFuzzDefaults()
financefuzz_defaults = FinanceFuzzDefaults()
