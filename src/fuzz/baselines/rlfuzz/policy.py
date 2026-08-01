"""RLFuzz policy: group-selection DQN + reference random argument generation."""

from __future__ import annotations

import random
from dataclasses import replace

import numpy as np

from ...config import RLConfig
from ...fuzzer.arg_sampling import build_address_pool, build_reentry_setup_call
from ...fuzzer.sol_interface import interface_eligible
from ...llm.agent import FuzzInput, TokenUsage
from ...rl.controller import RLController
from ..common.grouping import ATTACKER_GROUP, RLFUZZ_GROUPS, classify_functions
from .args import rlfuzz_arg_for_type, rlfuzz_payable_value

# Caller pool — RLFuzz does not differentiate callers, and our unified test
# harness declares a single attacker identity, so callers are always attacker.
_CALLER_POOL = ["attacker_address"]


def _rand_slice_size() -> int | None:
    """Reference per-tx dynamic-array length: uniform [1,5] with prob 0.8, else None."""
    return random.randint(1, 5) if random.random() >= 0.2 else None


class RLFuzzPolicy:
    """DQN over 5 function groups (+ attacker) + reference random argument generation.

    Constructed once per contract. After construction:
      .state_dim    is the encoder vector size
      .num_groups   = 6
      .method_name  = "RLFuzz"
    """

    method_name = "RLFuzz"
    num_groups = len(RLFUZZ_GROUPS)

    def __init__(
        self,
        contract_abi: list[dict],
        contract_source: str,
        state_dim: int,
        rl_config: RLConfig,
        initial_balance_native: int = 10,
        max_calls_per_item: int = 3,
        mode: str = "inline",
        external_addrs: list[str] | None = None,
    ):
        self.abi = contract_abi
        self.source = contract_source
        self.state_dim = state_dim
        self.initial_balance_native = initial_balance_native
        self.max_calls_per_item = max(1, max_calls_per_item)

        # Mode-aware address pool (aliases + externals + zero + random uint160).
        self.addr_pool = build_address_pool(mode, external_addrs)

        # Classify ABI functions into the RLFuzz groups.
        self.group_to_fns, self.fn_to_group = classify_functions(
            contract_abi, contract_source, groups=RLFUZZ_GROUPS,
        )

        # ABI metadata for arg generation. Class A: filter through interface_eligible
        # so `_fn_names` (used for the reentry target + follow-up calls in
        # _build_attacker_sequence) excludes tuple-typed, interface-uncallable
        # functions — matching `group_to_fns` (classify_functions already filters).
        self._abi_types: dict[str, list[str]] = {}
        self._abi_payable: set[str] = set()
        for item in interface_eligible(contract_abi):
            if item.get("type") == "function":
                self._abi_types[item["name"]] = [
                    inp.get("type", "") for inp in item.get("inputs", [])
                ]
                if item.get("stateMutability") == "payable":
                    self._abi_payable.add(item["name"])
        self._fn_names: list[str] = list(self._abi_types.keys())

        # DQN — reuse our shared controller. Override its state/action dims via a
        # copy of the user's RLConfig (so other hyperparameters stay aligned).
        policy_rl_cfg = replace(rl_config, state_dim=state_dim, action_dim=self.num_groups)
        self.rl = RLController(policy_rl_cfg)

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # The group-selection DQN is the only evolving state (args are random). Group
    # classification is deterministic from the ABI, rebuilt on resume.
    def checkpoint_state(self) -> dict:
        return {"rl": self.rl.state_dict()}

    def restore_checkpoint_state(self, d: dict) -> None:
        self.rl.load_state_dict(d["rl"])

    def learning_telemetry(self) -> dict:
        """Per-iteration DQN learning signals for the run-log `learning` block."""
        return {"epsilon": self.rl.epsilon, "td_loss": self.rl.last_loss,
                "q_chosen": self.rl.last_q_chosen}

    # ── Argument helpers ──────────────────────────────────────────────────────

    def _build_call(self, fn_name: str, slice_size: int | None) -> list:
        arg_types = self._abi_types.get(fn_name, [])
        args = [rlfuzz_arg_for_type(t, self.addr_pool, slice_size) for t in arg_types]
        value_wei = rlfuzz_payable_value(fn_name in self._abi_payable, self.initial_balance_native)
        return [fn_name, args, value_wei, random.choice(_CALLER_POOL)]

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def valid_groups(self) -> list[int]:
        return [i for i, fns in self.group_to_fns.items() if fns]

    def select_input(self, state: np.ndarray, iteration: int) -> tuple[FuzzInput, dict]:
        valid = self.valid_groups
        if not valid:
            # No callable functions — return an empty input; the loop will just record
            # zero coverage. This should not happen for a non-trivial contract.
            return (
                FuzzInput(calls=[], description="empty"),
                {"group_idx": 0, "group_name": "?", "fn_name": None},
            )

        slice_size = _rand_slice_size()
        group_idx = self.rl.select_strategy(state, valid_actions=valid)
        group_name = RLFUZZ_GROUPS[group_idx]
        fns = self.group_to_fns[group_idx]
        fn_name = random.choice(fns)

        # Attacker group → drive the unified Attacker harness.
        # We emit a setReentrantCall entry followed by 1..(max_seq-1) regular
        # calls (using the same random arg logic) so the callback actually fires.
        if group_name == ATTACKER_GROUP:
            calls = self._build_attacker_sequence(slice_size)
            fuzz_input = FuzzInput(
                calls=calls,
                description=f"rlfuzz:{group_name}/{fn_name}",
            )
            return fuzz_input, {
                "group_idx": group_idx,
                "group_name": group_name,
                "fn_name": fn_name,
            }

        # Build a short call sequence — paper uses single-function transactions per
        # action, but allowing a few diversifies execution.
        seq_len = random.randint(1, self.max_calls_per_item)
        calls = []
        for _ in range(seq_len):
            # Within a sequence, keep the action's group function as the primary,
            # but allow a random function from the same group on follow-ups so the
            # whole sequence reflects the group choice.
            this_fn = fn_name if not calls else random.choice(fns)
            calls.append(self._build_call(this_fn, slice_size))

        fuzz_input = FuzzInput(
            calls=calls,
            description=f"rlfuzz:{group_name}/{fn_name}",
        )
        meta = {
            "group_idx": group_idx,
            "group_name": group_name,
            "fn_name": fn_name,
        }
        return fuzz_input, meta

    def update(
        self,
        state: np.ndarray,
        action_meta: dict,
        reward: float,
        next_state: np.ndarray,
        done: bool = False,
    ) -> None:
        group_idx = int(action_meta.get("group_idx", 0))
        self.rl.store(state, group_idx, reward, next_state, done=done)
        self.rl.train_step()

    def token_stats(self) -> TokenUsage | None:
        return None  # RLFuzz uses no LLM

    # ── Attacker harness ─────────────────────────────────────────────────────

    def _build_attacker_sequence(self, slice_size: int | None) -> list:
        """Build [setReentrantCall, followup_call, ...] using random per-type args.

        Picks a target function from the ABI (prefers payable ones — those are the
        only ones whose callback flow makes re-entry meaningful), then emits regular
        follow-up calls so the configured callback actually fires.
        """
        if not self._fn_names:
            return []

        # Bias the re-entry target toward payable functions when any exist
        payable_fns = [f for f in self._fn_names if f in self._abi_payable]
        target_fn = random.choice(payable_fns) if payable_fns else random.choice(self._fn_names)
        target_arg_types = self._abi_types.get(target_fn, [])

        setup_call = build_reentry_setup_call(
            target_fn, target_arg_types,
            lambda t: rlfuzz_arg_for_type(t, self.addr_pool, slice_size),
        )

        # Follow-up calls: at least 1, up to max_calls_per_item - 1 (so the total
        # never exceeds max_calls_per_item). The follow-ups use attacker_address
        # as caller so the ETH callback flows through the configured attacker.
        n_followups = random.randint(1, max(1, self.max_calls_per_item - 1))
        followups = [
            self._build_call(random.choice(self._fn_names), slice_size)
            for _ in range(n_followups)
        ]
        return [setup_call] + followups
