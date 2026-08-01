"""Declarative method × dataset registry — the experiment-runner analogue of
`fuzz.report.REPORT_SPECS`.

`METHOD_SPECS` maps each fuzzing method to its entry function + hyperparameter
defaults + per-method knobs; `DATASET_SPECS` maps each dataset to its kind
(inline | fork) + result layout. `run.py` reads both to build one resumable
driver loop, replacing the 10 per-(method, dataset) scripts.

Adding a method = one `MethodSpec` line here + its `*_defaults` in
`fuzz.profiles`. No new runner file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from fuzz.baselines.financefuzz import run_financefuzz
from fuzz.baselines.llmfuzz import run_llmfuzz
from fuzz.baselines.madfuzz import run_madfuzz
from fuzz.baselines.randomfuzz import run_randomfuzz
from fuzz.baselines.rlfuzz import run_rlfuzz
from fuzz.main import run_fuzzing_loop
from fuzz.profiles import (
    financefuzz_defaults,
    llmfuzz_defaults,
    madfuzz_defaults,
    randomfuzz_defaults,
    rlfuzz_defaults,
    sscfuzz_cb_defaults,
    sscfuzz_defaults,
    sscfuzz_esb_defaults,
)


@dataclass(frozen=True)
class MethodSpec:
    """One fuzzing method's wiring.

    entry        — `(config, source, abi, *, verbose, debug, **extra) -> (bugs, run_log)`
    defaults     — the `*_defaults` object; `.materialize(mode=…)` builds the config
    uses_llm     — whether the profile's LLM_BACKEND applies (sets cfg.llm.backend)
    extra_kwargs — optional `(profile_module) -> dict` of method-specific entry kwargs
                   (madfuzz's use_llm_seed / llm_pool_prob)
    """

    name: str
    entry: Callable[..., tuple[list[dict], dict]]
    defaults: Any
    uses_llm: bool
    extra_kwargs: Optional[Callable[[Any], dict]] = None


METHOD_SPECS: dict[str, MethodSpec] = {
    "randomfuzz": MethodSpec("randomfuzz", run_randomfuzz, randomfuzz_defaults, uses_llm=False),
    "rlfuzz": MethodSpec("rlfuzz", run_rlfuzz, rlfuzz_defaults, uses_llm=False),
    "madfuzz": MethodSpec(
        "madfuzz", run_madfuzz, madfuzz_defaults, uses_llm=True,
        extra_kwargs=lambda p: {"use_llm_seed": p.USE_LLM_SEED, "llm_pool_prob": p.LLM_POOL_PROB},
    ),
    "llmfuzz": MethodSpec("llmfuzz", run_llmfuzz, llmfuzz_defaults, uses_llm=True),
    # The factored shared-per-arm-head DQN selector (the former default `sscfuzz`).
    # Renamed to `sscfuzz_dqn` 2026-07-15: the bare `sscfuzz` name is now an ALIAS
    # for the switching-bandit selector (see METHOD_ALIASES below) — the RQ3a finding
    # is that the encoded bandit, not the learned DQN, is the recommended selector.
    "sscfuzz_dqn": MethodSpec("sscfuzz_dqn", run_fuzzing_loop, sscfuzz_defaults, uses_llm=True),
    # Option C selector variant — same run_fuzzing_loop pipeline; the profile's
    # RLConfig.selector ("bandit") is the only difference. Writes to its own result
    # dir (output/experiment/<dataset>/sscfuzz_esb/), so nothing pools with the DQN.
    # `sscfuzz` (bare) resolves here via METHOD_ALIASES. See fuzz/profiles.py +
    # fuzz/rl/bandit.py. (The former sscfuzz_ms variant is folded into the DQN's
    # factored per-arm head.)
    "sscfuzz_esb": MethodSpec("sscfuzz_esb", run_fuzzing_loop, sscfuzz_esb_defaults, uses_llm=True),
    # Contextual-bandit selector variant (disjoint LinUCB) — same run_fuzzing_loop
    # pipeline; the profile's RLConfig.selector ("linucb") + emit_static=True are the
    # only differences. Own result dir (output/experiment/<dataset>/sscfuzz_cb/), so
    # nothing pools with canonical sscfuzz. See fuzz/profiles.py + rl/contextual_bandit.py.
    "sscfuzz_cb": MethodSpec("sscfuzz_cb", run_fuzzing_loop, sscfuzz_cb_defaults, uses_llm=True),
    # FinanceFuzz competitor: GA params come from its profile (not the experiment
    # profile module `p`); `generations` is derived from the regime budget by the runner.
    "financefuzz": MethodSpec(
        "financefuzz", run_financefuzz, financefuzz_defaults, uses_llm=False,
        extra_kwargs=lambda p: {
            "population": financefuzz_defaults.population,
            "p_crossover": financefuzz_defaults.p_crossover,
            "p_mutation": financefuzz_defaults.p_mutation,
            "max_individual_length": financefuzz_defaults.max_individual_length,
            "stale_reset": financefuzz_defaults.stale_reset,
            "equivalence_elite": financefuzz_defaults.equivalence_elite,
        },
    ),
}


# Method-name ALIASES resolved to a canonical METHOD_SPECS key before lookup.
# `sscfuzz` (bare, the legacy default name) redirects to the switching-bandit
# selector `sscfuzz_esb` — the RQ3a-recommended selector — so `sscfuzz` runs the
# bandit and lands in its result dir. The learned DQN keeps the explicit name
# `sscfuzz_dqn`. An alias is a valid CLI choice but is NOT iterated by `all`
# (which walks METHOD_SPECS.values() — one run per canonical method, no double-run).
METHOD_ALIASES: dict[str, str] = {
    "sscfuzz": "sscfuzz_esb",
}


def resolve_method(name: str) -> str:
    """Map a method name (possibly an alias) to its canonical METHOD_SPECS key."""
    return METHOD_ALIASES.get(name, name)


@dataclass(frozen=True)
class DatasetSpec:
    """One dataset's kind + result layout.

    kind            — "inline" (SmartBugs: source in JSON) | "fork" (DeFiHackLabs:
                      on-disk multifile tree + fork metadata).
    json_key        — `schema.load_dataset` key.
    results_subdir  — dataset subdir under ./output/experiment/ (one per dataset).
    filter_skip     — drop `skip=True` contracts before iterating (fork manifest
                      carries post-fetch skips; the inline set is pre-filtered).
    """

    name: str
    kind: str
    json_key: str
    results_subdir: str
    filter_skip: bool


DATASET_SPECS: dict[str, DatasetSpec] = {
    "smartbugs": DatasetSpec("smartbugs", "inline", "smartbugs", "smartbugs", filter_skip=False),
    "defihacklabs": DatasetSpec("defihacklabs", "fork", "defihacklabs", "defihacklabs", filter_skip=True),
}
