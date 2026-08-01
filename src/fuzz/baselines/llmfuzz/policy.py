"""LLMFuzz policy: LLM-only input generation, no RL, fallback to random.

Each iteration the policy uniformly selects one strategy from the ACTIVE roster —
both generation and mutation strategies, minus any gated in
`disabled_strategies` — and asks the LLM to generate (or mutate a corpus seed)
for it. No DQN; update() is a no-op. This makes LLMFuzz a clean RL-ablation of
SScFuzz: the same generation+mutation action space and gate, selected uniformly
instead of by the DQN.

History is maintained via LLMGenerator.record_run() so the model sees what has
been tried, and a corpus (LLMMutator) is grown from results so mutation strategies
have seeds. LLM failures fall back to random ABI sampling (built into
LLMGenerator.generate / LLMMutator.llm_mutate). Mutation strategies are only
eligible once the corpus holds at least `mutation_min_corpus_size` seeds.

Reentrancy usage: the reentrancy_probe strategy is in the pool; its caller_hints
include "attacker_address", so the LLM is prompted to emit
atk.setReentrantCall sequences when that strategy is selected.
"""

from __future__ import annotations

import random

import numpy as np

from ...config import LLMConfig, RLConfig
from ...fuzzer.mutator import CorpusEntry, LLMMutator
from ...llm.agent import FuzzInput, TokenUsage
from ...llm.generator import LLMGenerator
from ...llm.strategies import GENERATION_STRATEGIES, MUTATION_STRATEGIES


class LLMFuzzPolicy:
    """LLM-guided fuzzing without RL.

    Uniformly rotates through the active generation + mutation roster each
    iteration (gated by `disabled_strategies`). History is tracked so the LLM
    sees what has been tried, a corpus feeds the mutation strategies, and LLM
    failures fall back transparently to random ABI sampling.
    """

    method_name = "LLMFuzz"
    num_groups = 1  # no RL grouping — required by BaselineStateEncoder

    def __init__(
        self,
        contract_abi: list[dict],
        contract_source: str,
        llm_config: LLMConfig,
        state_dim: int,
        initial_balance_native: int = 10,
        ast: dict | None = None,
        target_name: str | None = None,
        debug: bool = False,
        disabled_strategies: tuple[str, ...] = (),
        rl_config: RLConfig | None = None,
    ):
        self.abi = contract_abi
        self.source = contract_source
        self.state_dim = state_dim
        self.debug = debug
        # Count iterations where the LLM exhausted its retries and fell back to
        # random ABI sampling (surfaced as the "Fallback" line in the Done panel).
        self.fallback_count = 0
        self._generator = LLMGenerator(llm_config, initial_balance_native)
        self._generator.setup_abi(contract_abi)
        if ast is not None or target_name is not None:
            self._generator.set_source_context(ast, target_name)

        # Active roster (gate applied) — the same mechanism as SScFuzz.
        gated = set(disabled_strategies or ())
        self._active_gen = [g for g in GENERATION_STRATEGIES if g not in gated]
        self._active_mut = [m for m in MUTATION_STRATEGIES if m not in gated]

        # Corpus for the mutation strategies — shares the generator's LLM client so
        # generation and mutation see one unified run history.
        self._rl = rl_config or RLConfig()
        self._mutator = LLMMutator(
            self._rl, abi=contract_abi,
            initial_balance_native=initial_balance_native,
            shared_llm=self._generator._llm,
        )
        # Exposed so the shared loop's Done panel reports corpus size.
        self.seed_pool = self._mutator

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # No DQN here (LLMFuzz rotates strategies). Evolving state = the mutation
    # corpus, the fallback counter, and the shared LLM client's history/tokens.
    def checkpoint_state(self) -> dict:
        return {
            "mutator": self._mutator.checkpoint_state(),
            "fallback_count": self.fallback_count,
            "llm": self._generator._llm.checkpoint_state(),
        }

    def restore_checkpoint_state(self, d: dict) -> None:
        self._mutator.restore_checkpoint_state(d["mutator"])
        self.fallback_count = d.get("fallback_count", 0)
        self._generator._llm.restore_checkpoint_state(d["llm"])

    # ── Public API ────────────────────────────────────────────────────────────

    def select_input(self, state: np.ndarray, iteration: int) -> tuple[FuzzInput, dict]:
        corpus_ready = len(self._mutator) >= self._rl.mutation_min_corpus_size
        pool = list(self._active_gen)
        if corpus_ready and self._active_mut:
            pool += self._active_mut
        pick = random.choice(pool) if pool else "exploration"

        self._generator._llm.last_fallback_reason = None
        is_mut = pick in self._active_mut and corpus_ready

        seed_entry = self._mutator.sample_seed() if is_mut else None
        if is_mut and seed_entry is None:
            is_mut = False  # corpus race — degrade to generation

        if is_mut:
            mutation_strategy = pick
            strategy = seed_entry.strategy  # seed's gen strategy = LLM context
            fuzz_inputs = self._mutator.llm_mutate(
                seed_entry, mutation_strategy, self.source, self.abi,
                n=1, debug=self.debug,
            )
            child_step = {"mode": "mut", "name": mutation_strategy, "iter": iteration}
            for fi in fuzz_inputs:
                fi.lineage = list(seed_entry.fuzz_input.lineage) + [child_step]
            fi = fuzz_inputs[0] if fuzz_inputs else FuzzInput(calls=[], description="llmfuzz:empty")
            mode = "mutate"
            run_label = mutation_strategy
            seed_branches = seed_entry.bc_branches_this_run
            group_name = f"mut:{mutation_strategy}"
        else:
            strategy = pick
            mutation_strategy = None
            results = self._generator.generate(
                self.source, self.abi, strategy=strategy, n=1, debug=self.debug,
            )
            fi = results[0] if results else FuzzInput(calls=[], description="llmfuzz:empty")
            fi.lineage = [{"mode": "gen", "name": strategy, "iter": iteration}]
            mode = "generate"
            run_label = strategy
            seed_branches = None
            group_name = strategy

        # generate()/llm_mutate() set last_fallback_reason to "llm_exhausted: …"
        # only when all retries fail.
        fr = self._generator._llm.last_fallback_reason
        if fr and fr.startswith("llm_exhausted"):
            self.fallback_count += 1

        self._last_iteration = iteration
        fn_name = fi.calls[0][0] if fi.calls else None
        return fi, {
            "group_idx": 0,
            "group_name": group_name,
            "fn_name": fn_name,
            "strategy": strategy,
            "mutation_strategy": mutation_strategy,
            "mode": mode,
            "seed_branches": seed_branches,
            "run_label": run_label,
            "llm_prompt": self._generator._llm.last_prompt,
            "llm_response": self._generator._llm.last_response,
            "fallback": fr is not None,
            "fallback_reason": fr,
        }

    def update(
        self,
        state: np.ndarray,
        action_meta: dict,
        reward: float,
        next_state: np.ndarray,
        done: bool = False,
    ) -> None:
        pass  # no RL in LLMFuzz

    def on_result(
        self,
        fuzz_input: FuzzInput,
        result: object,
        reward: float,
        action_meta: dict,
    ) -> None:
        """Record the run into the LLM's history and grow the mutation corpus."""
        strategy = action_meta.get("strategy", "exploration")
        mode = action_meta.get("mode", "generate")
        run_label = action_meta.get("run_label", strategy)
        self._generator.record_run(
            fuzz_input=fuzz_input,
            reward=reward,
            forge_status=getattr(result, "forge_status", ""),
            raw_reason=getattr(result, "raw_reason", "") or "",
            new_branches=getattr(result, "new_bc_branches", 0),
            decoded_logs=list(getattr(result, "decoded_logs", []) or []),
            strategy=run_label,
            mode=mode,
            fallback=bool(action_meta.get("fallback", False)),
        )
        # Admit every run unconditionally — Group A/B curation inside add() decides
        # survival (same policy as SScFuzz). The seed's context strategy is the
        # generation strategy (for mutations, the parent's).
        self._mutator.add(CorpusEntry(
            fuzz_input=fuzz_input,
            reward=reward,
            strategy=strategy,
            bc_branches_this_run=getattr(result, "bc_branches_this_run", frozenset()),
            iteration=getattr(self, "_last_iteration", 0),
            bug_signal_found=getattr(result, "bug_signal_found", False),
        ))

    def token_stats(self) -> TokenUsage | None:
        return self._generator.token_stats
