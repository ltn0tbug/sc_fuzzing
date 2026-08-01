"""Configuration for the baseline fuzzers (RLFuzz, MADFuzz)."""

from dataclasses import dataclass, field
from typing import Optional

from ...config import ForkConfig, LLMConfig, RLConfig


@dataclass
class BaselineConfig:
    """Run configuration shared by both baselines.

    `rl` is reused from our project so the DQN hyperparameters are identical
    across methods (the only thing changing per method is state_dim / action_dim,
    which the policy passes in when constructing its own RLConfig instance).

    `llm` is only used by MADFuzz for one-shot seed generation at startup.
    """
    max_iterations: int = 200
    contract_path: str = ""
    contract_name: str = ""
    foundry_project: str = ""
    output_dir: str = "output"
    initial_balance_native: int = 10
    max_calls_per_item: int = 12     # synced with LLMConfig.max_calls_per_item
    # Reward dispatch — all baselines use the same generic reward function
    # (see compute_reward in fuzzer/reward.py). "exploration" is the most
    # neutral choice (coverage + BUG_SIGNAL + small revert bonuses).
    reward_strategy: str = "exploration"
    rl: RLConfig = field(default_factory=RLConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    # Fork mode (DeFiHackLabs dataset). Plumbed through to FoundryFuzzer.
    fork: Optional[ForkConfig] = None
    # Declared external contracts (dataset row's `extend.external`, same source
    # sscfuzz uses). Populated by the experiment runner. Passed to the FoundryFuzzer
    # so external addresses render, and to RLFuzz/MADFuzz so their mode-aware address
    # pool (fuzzer.arg_sampling.build_address_pool) includes the external addresses.
    # None/[] → target-only.
    external: Optional[list] = None
    # Co-located dependency deploys (`extend.pre_deploy`) + post-deploy wiring
    # (`extend.setup_calls`), same as the sscfuzz/main path. Populated by the
    # experiment runner (run.py) and forwarded to FoundryFuzzer so contracts that
    # reference a sibling dep (e.g. a SmartBugs bank whose Deposit calls
    # Log.AddMessage) are deployed + wired in setUp. Without these the dep stays at
    # its dead default address and the target's calls revert. None → no deps.
    pre_deploy: Optional[list] = None
    setup_calls: Optional[list] = None
    # Strategy names gated off for policies that select over the generation +
    # mutation roster (LLMFuzz). Same mechanism/semantics as
    # FuzzerConfig.disabled_strategies — the policy drops these from its active
    # pool. Empty = full roster. Baselines that don't use the roster ignore it.
    disabled_strategies: tuple[str, ...] = ()
    # ── Iteration-level checkpointing (runtime; set by the experiment runner) ──
    # Mirror of FuzzerConfig's fields so common/loop.py resumes baselines the same
    # way sscfuzz resumes. None/≤0 → disabled. See fuzz/checkpoint.py.
    checkpoint_path: Optional[str] = None
    checkpoint_every: int = 0
    # On clean completion, keep a FINAL complete checkpoint at the true last
    # iteration so a later higher-max_iterations run continues. See FuzzerConfig.
    keep_checkpoint: bool = False


def resolve_external_addrs(config: "BaselineConfig") -> list[str]:
    """Resolve `config.external` to the list of hex addresses for the address pool.

    RLFuzz / MADFuzz feed these into fuzzer.arg_sampling.build_address_pool so the
    fuzzer can target the declared external contracts by address. Callable and
    data-only externals both carry an `address`; entries missing one are skipped.
    """
    return [e.get("address") for e in (getattr(config, "external", None) or []) if e.get("address")]
