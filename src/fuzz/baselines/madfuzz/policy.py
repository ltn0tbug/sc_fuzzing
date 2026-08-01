"""MADFuzz policy.

Method:
  - One group-selection DQN over the 6 groups (RLFuzz's 5 + attacker); the
    reference "status" view/pure group is dropped so selection matches RLFuzz.
  - Five per-type DQNs (uint, int, bool, addr, byte) — each outputs an index that
    the decoders in madfuzz/args.py turn into a value:
      uint → 257-action value-range table
      int  → 255-action signed-segment table
      bool → 2 actions
      addr → len(addr_pool) actions (index into the mode-aware address pool)
      byte → 256 actions, applied PER BYTE of a bytes/bytesN arg
    Strings are pure random (no DQN), matching the reference.
  - LLM-generated seed pool sampled with probability `llm_pool_prob` at each step
    (hybrid exploration). When sampled, the (fn, args) sequence from the pool
    overrides the per-type DQN output for that step.

We do NOT use DRQN (recurrent). Our shared DQNNetwork is a feedforward MLP; the
state already encodes recent history (coverage velocity, action counts, etc.) so
the recurrent state would mostly be redundant for the contract sizes we run.
This is documented in the comparison notes as an intentional adaptation.
"""

from __future__ import annotations

import random
from dataclasses import replace

import numpy as np

from ...config import LLMConfig, RLConfig
from ...fuzzer.arg_sampling import build_address_pool, build_payable_value, build_reentry_setup_call
from ...fuzzer.sol_interface import interface_eligible
from ...llm.agent import FuzzInput, TokenUsage
from ...rl.controller import RLController
from ..common.grouping import ATTACKER_GROUP, MADFUZZ_GROUPS, classify_functions
from .args import (
    ACTION_DIMS,
    bucket_of,
    byte_len,
    decode_bool,
    decode_byte_seq,
    decode_int,
    decode_uint,
    random_string,
    type_bit_size,
)
from .seed_gen import generate_seed_pool

_CALLER_POOL = ["attacker_address"]


class MADFuzzPolicy:
    """Group DQN + per-type arg DQNs + LLM seed pool."""

    method_name = "MADFuzz"
    num_groups = len(MADFUZZ_GROUPS)

    def __init__(
        self,
        contract_abi: list[dict],
        contract_source: str,
        state_dim: int,
        rl_config: RLConfig,
        llm_config: LLMConfig,
        initial_balance_native: int = 10,
        max_calls_per_item: int = 3,
        llm_pool_prob: float = 0.3,
        use_llm_seed: bool = True,
        ast: dict | None = None,
        target_name: str | None = None,
        mode: str = "inline",
        external_addrs: list[str] | None = None,
    ):
        self.abi = contract_abi
        self.source = contract_source
        self.state_dim = state_dim
        self.initial_balance_native = initial_balance_native
        self.max_calls_per_item = max(1, max_calls_per_item)
        self.llm_pool_prob = llm_pool_prob

        # Mode-aware address pool (aliases + externals + zero + random uint160).
        # Built once so the per-arg address DQN's index→address mapping is stable.
        self.addr_pool = build_address_pool(mode, external_addrs)

        self.group_to_fns, self.fn_to_group = classify_functions(
            contract_abi, contract_source, groups=MADFUZZ_GROUPS,
        )

        # Class A: filter through interface_eligible so the reentry target + follow-up
        # pool (built from _abi_types.keys()) excludes tuple-typed, interface-uncallable
        # functions — matching group_to_fns (classify_functions already filters).
        self._abi_types: dict[str, list[str]] = {}
        self._abi_payable: set[str] = set()
        for item in interface_eligible(contract_abi):
            if item.get("type") == "function":
                self._abi_types[item["name"]] = [
                    inp.get("type", "") for inp in item.get("inputs", [])
                ]
                if item.get("stateMutability") == "payable":
                    self._abi_payable.add(item["name"])

        # Group selection DQN
        self.rl_group = RLController(
            replace(rl_config, state_dim=state_dim, action_dim=self.num_groups)
        )

        # Per-type argument DQNs. Fixed dims (257/255/2/256) for uint/int/bool/byte;
        # addr's action space is the address-pool size.
        arg_dims = dict(ACTION_DIMS)
        arg_dims["addr"] = max(1, len(self.addr_pool))
        self.rl_args: dict[str, RLController] = {
            bucket: RLController(
                replace(rl_config, state_dim=state_dim, action_dim=dim)
            )
            for bucket, dim in arg_dims.items()
        }

        # LLM seed pool — list of FuzzInput-shaped dicts (full sequences with
        # optional setReentrantCall first entry).  Empty list = "no LLM seeds".
        self.seed_pool: list[dict] = []
        self._llm = None
        # One-shot seed-gen status for the Done panel: None=disabled,
        # True=pool generated, False=LLM call failed / empty pool.
        self.seed_gen_ok: bool | None = None
        if use_llm_seed:
            try:
                self.seed_pool, self._llm = generate_seed_pool(
                    llm_config, contract_source, contract_abi,
                    initial_balance_native=initial_balance_native,
                    ast=ast,
                    target_name=target_name,
                )
                self.seed_gen_ok = len(self.seed_pool) > 0
            except Exception:
                # LLM unavailable — degrade gracefully to "no seed pool, no LLM tokens"
                self.seed_pool = []
                self._llm = None
                self.seed_gen_ok = False

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # Group DQN + per-bucket arg DQNs are the evolving learners; the LLM seed pool
    # is one-shot (regenerated by __init__ on resume, then overwritten by the
    # restored pool so the run continues from the checkpointed seeds).
    def checkpoint_state(self) -> dict:
        return {
            "rl_group": self.rl_group.state_dict(),
            "rl_args": {k: v.state_dict() for k, v in self.rl_args.items()},
            "seed_pool": self.seed_pool,
            "seed_gen_ok": self.seed_gen_ok,
        }

    def restore_checkpoint_state(self, d: dict) -> None:
        self.rl_group.load_state_dict(d["rl_group"])
        for k, sd in d.get("rl_args", {}).items():
            if k in self.rl_args:
                self.rl_args[k].load_state_dict(sd)
        if d.get("seed_pool") is not None:
            self.seed_pool = list(d["seed_pool"])
        self.seed_gen_ok = d.get("seed_gen_ok", self.seed_gen_ok)

    def learning_telemetry(self) -> dict:
        """Per-iteration DQN learning signals (the strategic group-selection DQN)."""
        return {"epsilon": self.rl_group.epsilon, "td_loss": self.rl_group.last_loss,
                "q_chosen": self.rl_group.last_q_chosen}

    # ── Per-type argument generation (DQN-indexed) ────────────────────────────

    def _gen_arg(self, sol_type: str, state: np.ndarray) -> tuple[object, list[tuple[str, int]]]:
        """Generate one argument value + the (bucket, idx) DQN decisions it made.

        Array types are sampled as a length-1 array over the base element type.
        Returns (value, actions) where `actions` records every per-type DQN choice
        so credit can flow back in `update`.
        """
        is_array = sol_type.strip().endswith("]") and "[" in sol_type
        bucket = bucket_of(sol_type)
        actions: list[tuple[str, int]] = []

        if bucket == "string":
            value: object = random_string()          # no DQN
        elif bucket == "bytes":
            n = byte_len(sol_type)
            byte_actions = [self.rl_args["bytes"].select_strategy(state) % 256 for _ in range(n)]
            value = decode_byte_seq(byte_actions)
            actions.extend(("bytes", a) for a in byte_actions)
        elif bucket == "uint":
            dim = ACTION_DIMS["uint"]
            idx = self.rl_args["uint"].select_strategy(state) % dim
            value = str(decode_uint(idx, type_bit_size(sol_type)))
            actions.append(("uint", idx))
        elif bucket == "int":
            dim = ACTION_DIMS["int"]
            idx = self.rl_args["int"].select_strategy(state) % dim
            value = str(decode_int(idx, type_bit_size(sol_type)))
            actions.append(("int", idx))
        elif bucket == "bool":
            idx = self.rl_args["bool"].select_strategy(state) % 2
            value = decode_bool(idx)
            actions.append(("bool", idx))
        else:  # addr
            pool_size = max(1, len(self.addr_pool))
            idx = self.rl_args["addr"].select_strategy(state) % pool_size
            value = self.addr_pool[idx]
            actions.append(("addr", idx))

        if is_array:
            value = [value]
        return value, actions

    def _gen_args(self, fn_name: str, state: np.ndarray) -> tuple[list, list[tuple[str, int]]]:
        args: list = []
        arg_actions: list[tuple[str, int]] = []
        for sol_type in self._abi_types.get(fn_name, []):
            value, acts = self._gen_arg(sol_type, state)
            args.append(value)
            arg_actions.extend(acts)
        return args, arg_actions

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def valid_groups(self) -> list[int]:
        return [i for i, fns in self.group_to_fns.items() if fns]

    def select_input(self, state: np.ndarray, iteration: int) -> tuple[FuzzInput, dict]:
        valid = self.valid_groups
        if not valid:
            return (
                FuzzInput(calls=[], description="empty"),
                {"group_idx": 0, "group_name": "?", "fn_name": None,
                 "arg_actions": [], "used_llm_seed": False},
            )

        # Hybrid exploration (MADFuzz paper §4): with probability llm_pool_prob × ε,
        # sample a complete FuzzInput sequence from the LLM seed pool. The seed
        # may contain a setReentrantCall entry — its dominant group is classified
        # so the group DQN still gets credit for the action.
        if (
            self.seed_pool
            and random.random() < self.llm_pool_prob
            and random.random() < max(self.rl_group.epsilon, 0.2)
        ):
            seed = random.choice(self.seed_pool)
            group_idx = self._classify_seed_group(seed)
            group_name = MADFUZZ_GROUPS[group_idx] if 0 <= group_idx < len(MADFUZZ_GROUPS) else "?"
            fuzz_input = FuzzInput(
                calls=[list(c) for c in seed.get("calls", [])],
                description=f"madfuzz:llm-seed/{group_name}",
            )
            return fuzz_input, {
                "group_idx": group_idx,
                "group_name": group_name,
                "fn_name": seed["calls"][0][0] if seed.get("calls") else None,
                "arg_actions": [],     # no per-type DQN decisions on seed-sampled steps
                "used_llm_seed": True,
            }

        group_idx = self.rl_group.select_strategy(state, valid_actions=valid)
        group_name = MADFUZZ_GROUPS[group_idx]
        fns = self.group_to_fns[group_idx]
        fn_name = random.choice(fns)

        # Attacker group → drive the unified Attacker harness.
        # Args for the re-entry call use the same per-type DQNs as regular calls,
        # so the existing arg-selection mechanism is preserved.
        if group_name == ATTACKER_GROUP:
            calls, arg_actions = self._build_attacker_sequence(state)
            fuzz_input = FuzzInput(
                calls=calls,
                description=f"madfuzz:{group_name}/{fn_name}",
            )
            return fuzz_input, {
                "group_idx": group_idx,
                "group_name": group_name,
                "fn_name": fn_name,
                "arg_actions": arg_actions,
                "used_llm_seed": False,
            }

        # Regular per-type DQN path: each arg's value is chosen by the matching
        # per-type DQN. arg_actions records the (bucket, idx) decisions so credit
        # flows back via update().
        args, arg_actions = self._gen_args(fn_name, state)
        is_payable = fn_name in self._abi_payable
        value_wei = build_payable_value(is_payable, self.initial_balance_native)
        caller = random.choice(_CALLER_POOL)

        calls = [[fn_name, args, value_wei, caller]]
        # Optional short sequence for state-dependent bugs
        seq_extra = random.randint(0, max(0, self.max_calls_per_item - 1))
        for _ in range(seq_extra):
            extra_fn = random.choice(fns)
            extra_args, extra_acts = self._gen_args(extra_fn, state)
            arg_actions.extend(extra_acts)
            extra_payable = extra_fn in self._abi_payable
            calls.append([
                extra_fn, extra_args,
                build_payable_value(extra_payable, self.initial_balance_native),
                random.choice(_CALLER_POOL),
            ])

        fuzz_input = FuzzInput(
            calls=calls,
            description=f"madfuzz:{group_name}/{fn_name}",
        )
        meta = {
            "group_idx": group_idx,
            "group_name": group_name,
            "fn_name": fn_name,
            "arg_actions": arg_actions,
            "used_llm_seed": False,
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
        # Update group DQN
        group_idx = int(action_meta.get("group_idx", 0))
        self.rl_group.store(state, group_idx, reward, next_state, done=done)
        self.rl_group.train_step()

        # Update per-type arg DQNs with the same reward signal (joint credit assignment)
        for bucket, idx in action_meta.get("arg_actions", []):
            ctrl = self.rl_args.get(bucket)
            if ctrl is None:
                continue
            ctrl.store(state, int(idx), reward, next_state, done=done)
            ctrl.train_step()

    def token_stats(self) -> TokenUsage | None:
        return self._llm.token_stats if self._llm is not None else None

    # ── LLM seed pool helpers ────────────────────────────────────────────────

    def _classify_seed_group(self, seed: dict) -> int:
        """Pick a group_idx representing this seed's dominant action.

        Seeds with `atk.setReentrantCall` map to the attacker group; all
        others use the group of their first non-setup call. This gives the group
        DQN a sensible credit signal for seed-sampled steps without bypassing it.
        """
        calls = seed.get("calls", [])
        for c in calls:
            if c and isinstance(c[0], str) and c[0] == "atk.setReentrantCall":
                try:
                    return MADFUZZ_GROUPS.index(ATTACKER_GROUP)
                except ValueError:
                    break
        for c in calls:
            if c and isinstance(c[0], str) and c[0] != "atk.setReentrantCall":
                idx = self.fn_to_group.get(c[0])
                if idx is not None:
                    return idx
        return self.valid_groups[0] if self.valid_groups else 0

    # ── Attacker harness ─────────────────────────────────────────────────────

    def _build_attacker_sequence(
        self, state: np.ndarray,
    ) -> tuple[list, list[tuple[str, int]]]:
        """Build [setReentrantCall, followup_call, ...] using per-type DQN args.

        Returns (calls, arg_actions). arg_actions records the (bucket, idx) the
        per-type DQNs chose for the re-entry target's and follow-ups' arguments,
        so credit can flow back via `update`.
        """
        if not self._abi_types:
            return [], []

        fn_names = list(self._abi_types.keys())
        payable_fns = [f for f in fn_names if f in self._abi_payable]
        target_fn = random.choice(payable_fns) if payable_fns else random.choice(fn_names)
        target_arg_types = self._abi_types.get(target_fn, [])

        arg_actions: list[tuple[str, int]] = []

        def _reentrant_arg(sol_type: str):
            value, acts = self._gen_arg(sol_type, state)
            arg_actions.extend(acts)
            return value

        setup_call = build_reentry_setup_call(target_fn, target_arg_types, _reentrant_arg)

        # Follow-up calls: at least 1, capped at max_calls_per_item - 1.
        n_followups = random.randint(1, max(1, self.max_calls_per_item - 1))
        followups = []
        for _ in range(n_followups):
            this_fn = random.choice(fn_names)
            extra_args, extra_acts = self._gen_args(this_fn, state)
            arg_actions.extend(extra_acts)
            this_payable = this_fn in self._abi_payable
            followups.append([
                this_fn, extra_args,
                build_payable_value(this_payable, self.initial_balance_native),
                "attacker_address",
            ])
        return [setup_call] + followups, arg_actions
