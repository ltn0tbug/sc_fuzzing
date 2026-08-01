"""Baseline state encoder.

Adapted from the RLFuzz / MADFuzz state design. This is a REDUCED reproduction:
the published state (verified against ref/rlf + ref/madfuzz, which share it —
MADFuzz forks RLFuzz's MethodRecord.to_vec byte-for-byte) is a per-METHOD raw
365-dim vector = 65 numeric SC+F features + a 300-dim Word2Vec of the function
name (ref/rlf/ilf_w2v.pkl), compressed to 100-dim by a pretrained net and fed to
a DRQN picking one of 5 function groups. We DROP the Word2Vec name embedding and
the 50-opcode-per-function profile (opcode-level features we can't get cheaply
from Foundry) and flatten function-granularity into groups, capturing the spirit
(SC features + F features) with a fixed-size vector built from coverage, group
action history, recent reward / revert signals, and ABI metadata. Completing a
faithful build is a documented future task (todo.md "Faithful RLFuzz / MADFuzz
state"); the dropped features are F1-static (constant within a per-contract run),
so they only matter under cross-contract carryover — see
research/rl_design/state_space_design.md §3.1 + §4.1.

State layout (configurable via `num_groups`):
  [0]                 coverage_ratio
  [1]                 coverage_velocity
  [2 .. 2+G-1]        normalized action-count per group (sum-to-≤1)
  [2+G]               revert_rate (recent window)
  [2+G+1]             avg_reward (recent window, tanh-squashed)
  [2+G+2]             stuck_counter / 100
  [2+G+3]             iter_progress
  [2+G+4]             num_functions / 50
  [2+G+5]             num_payable / 20
  [2+G+6]             has_external_calls (0/1)
  [2+G+7]             cyclomatic_complexity / 50
  [2+G+8]             distinct_fns_called / num_functions (corpus diversity)

Total dim = 11 + G. Both RLFuzz and MADFuzz use G=6 (5 classification groups +
attacker) → state_dim 17.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

import numpy as np

from ...fuzzer.foundry import FuzzResult
from ...fuzzer.state import ContractFeatures


@dataclass
class BaselineState:
    """Per-method baseline state buffer."""
    coverage_history: deque = field(default_factory=lambda: deque(maxlen=10))
    reward_history: deque   = field(default_factory=lambda: deque(maxlen=20))
    revert_history: deque   = field(default_factory=lambda: deque(maxlen=20))
    action_counts: np.ndarray | None = None
    stuck_counter: int = 0
    last_coverage: float = 0.0
    iter_count: int = 0
    distinct_fns_called: set = field(default_factory=set)


class BaselineStateEncoder:
    """Encodes baseline state into a fixed-size vector for the policy network."""

    def __init__(
        self,
        contract_features: ContractFeatures,
        num_groups: int,
        max_iterations: int,
    ):
        self.features = contract_features
        self.num_groups = num_groups
        self.max_iterations = max(1, max_iterations)
        self.state = BaselineState(action_counts=np.zeros(num_groups, dtype=np.float32))

    @property
    def state_dim(self) -> int:
        return 11 + self.num_groups

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # BaselineState (deques/ndarray/set) is entirely the evolving accumulator;
    # capture/restore it wholesale. Static `features`/`num_groups` are rebuilt.
    def checkpoint_state(self) -> dict:
        return {"state": self.state}

    def restore_checkpoint_state(self, d: dict) -> None:
        if d.get("state") is not None:
            self.state = d["state"]

    def encode(self) -> np.ndarray:
        s = self.state
        vec = np.zeros(self.state_dim, dtype=np.float32)

        # [0] coverage_ratio (latest)
        vec[0] = s.coverage_history[-1] if s.coverage_history else 0.0

        # [1] coverage velocity (mean of deltas over the window)
        if len(s.coverage_history) >= 2:
            deltas = np.diff(np.array(s.coverage_history, dtype=np.float32))
            vec[1] = float(deltas.mean())

        # [2 .. 2+G-1] action-count per group, normalized so the sum is ≤ 1
        total_actions = float(s.action_counts.sum()) if s.action_counts is not None else 0.0
        if total_actions > 0:
            vec[2 : 2 + self.num_groups] = s.action_counts / total_actions
        offset = 2 + self.num_groups

        # [+0] revert_rate
        vec[offset + 0] = float(np.mean(s.revert_history)) if s.revert_history else 0.0
        # [+1] avg_reward (tanh-squashed so it stays in [-1, 1])
        if s.reward_history:
            avg_r = float(np.mean(s.reward_history))
            vec[offset + 1] = float(np.tanh(avg_r / 50.0))
        # [+2] stuck counter
        vec[offset + 2] = min(s.stuck_counter / 100.0, 1.0)
        # [+3] iteration progress
        vec[offset + 3] = min(s.iter_count / self.max_iterations, 1.0)
        # [+4..+7] static contract features
        vec[offset + 4] = min(self.features.num_functions / 50.0, 1.0)
        vec[offset + 5] = min(self.features.num_payable / 20.0, 1.0)
        vec[offset + 6] = float(self.features.has_external_calls)
        vec[offset + 7] = min(self.features.cyclomatic_complexity / 50.0, 1.0)
        # [+8] distinct functions called (diversity)
        num_fns = max(1, self.features.num_functions)
        vec[offset + 8] = min(len(s.distinct_fns_called) / num_fns, 1.0)

        return vec

    def update(
        self,
        group_idx: int,
        result: FuzzResult,
        reward: float,
        fn_names_used: Iterable[str] = (),
    ) -> None:
        s = self.state
        s.coverage_history.append(result.coverage)
        s.reward_history.append(reward)
        s.revert_history.append(1.0 if result.reverted else 0.0)
        if s.action_counts is not None and 0 <= group_idx < self.num_groups:
            s.action_counts[group_idx] += 1
        if result.coverage <= s.last_coverage:
            s.stuck_counter += 1
        else:
            s.stuck_counter = 0
        s.last_coverage = result.coverage
        s.iter_count += 1
        for fn in fn_names_used:
            s.distinct_fns_called.add(fn)
