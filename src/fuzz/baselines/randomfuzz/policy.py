"""RandomFuzz policy: pure uniform random ABI sampling, no RL, no LLM."""

from __future__ import annotations

import numpy as np

from ...llm.agent import FuzzInput, TokenUsage
from .generator import pure_random_fuzz_input


class RandomFuzzPolicy:
    """Purely random fuzzing — no DQN, no LLM.

    Every iteration samples a random call sequence via `pure_random_fuzz_input`
    (full-range integers, random uint160 addresses, random-length bytes/strings).
    Reentrancy is a uniform member of the selectable-function pool — no fixed
    budget. No learning takes place; `update()` is a no-op.
    """

    method_name = "RandomFuzz"
    num_groups = 1  # single trivial group; required by BaselineStateEncoder

    def __init__(
        self,
        contract_abi: list[dict],
        state_dim: int,
        initial_balance_native: int = 10,
        max_calls_per_item: int = 12,
        mode: str = "inline",
    ):
        self.abi = contract_abi
        self.state_dim = state_dim
        self.initial_balance_native = initial_balance_native
        self.max_calls_per_item = max(1, max_calls_per_item)
        self.mode = mode

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # RandomFuzz has no learner; continuity is entirely the process RNG (restored
    # globally by the loop). These are no-ops so the loop can treat every policy
    # uniformly.
    def checkpoint_state(self) -> dict:
        return {}

    def restore_checkpoint_state(self, d: dict) -> None:
        pass

    # ── Public API ────────────────────────────────────────────────────────────

    def select_input(self, state: np.ndarray, iteration: int) -> tuple[FuzzInput, dict]:
        raw = pure_random_fuzz_input(
            self.abi,
            max_calls=self.max_calls_per_item,
            initial_balance_native=self.initial_balance_native,
            mode=self.mode,
        )
        fi = FuzzInput.from_dict(raw)
        fn_name = fi.calls[0][0] if fi.calls else None
        return fi, {"group_idx": 0, "group_name": "random", "fn_name": fn_name}

    def update(
        self,
        state: np.ndarray,
        action_meta: dict,
        reward: float,
        next_state: np.ndarray,
        done: bool = False,
    ) -> None:
        pass  # no learning in RandomFuzz

    def token_stats(self) -> TokenUsage | None:
        return None
