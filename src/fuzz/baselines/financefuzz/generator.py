"""FinanceFuzz seed generation — port of ConFuzzius `engine/components/generator.py`.

Faithful to FinanceFuzz's *model* (their initial-seed generation), adapted to run
on our Foundry harness instead of the instrumented py-evm:

  - ABI → per-function argument types (the `interface`); functions rotated through a
    `CircularSet` ring buffer so every function is exercised (upstream
    `function_circular_buffer`).
  - Boundary-aware argument sampling: `UINT_MAX` / `INT_MAX` / `INT_MIN` edge seeds
    biased via the same `get_random_unsigned_integer` / `get_random_signed_integer`
    triangular-seed trick, plus per-(function, arg) value pools (`arguments_pool`)
    that mutation/feedback refill.
  - Accounts drawn from a small caller pool; `amount` (msg.value) from a 0/1 pool
    (payable functions additionally seeded with a fundable value).

Documented backend adaptations (see .README_AGENT.md):
  - An individual is emitted directly as our harness call-list `[name, args, value_wei,
    caller]`; `Tx` is the in-flight gene.
  - Dropped the py-evm-only environment fields (`call_return`, `extcodesize`,
    `returndatasize`, `blocknumber`) — forge cannot honour them. `timestamp` is not
    carried on the gene either: FinanceFuzz's timestamp detector overrides
    `block.timestamp` at the EVM level regardless of the seed, which we reproduce with
    `vm.warp` in the equivalence executor.
"""

from __future__ import annotations

import collections
import random
from dataclasses import dataclass, field
from typing import Any, Iterable

from ...fuzzer.sol_interface import interface_eligible

# ── Boundary tables (upstream generator.py) ───────────────────────────────────
UINT_MAX = {n: (1 << (8 * n)) - 1 for n in range(1, 33)}
INT_MAX = {n: (1 << (8 * n - 1)) - 1 for n in range(1, 33)}
INT_MIN = {n: -(1 << (8 * n - 1)) for n in range(1, 33)}

MAX_RING_BUFFER_LENGTH = 10
MAX_ARRAY_LENGTH = 2

# Caller pool — our harness funds these two named actors in setUp (attacker +
# reentrancy attacker). Two distinct senders are enough for the TOD detector to
# build a non-trivial reordering. `deployer_address` is intentionally excluded
# (never a caller, per the harness contract).
DEFAULT_CALLERS = ["attacker_address"]

# Concrete address values for address-typed arguments. Mirrors FinanceFuzz drawing
# addresses from its accounts pool; we render concrete 20-byte hex so inline-mode arg
# rendering stays simple. `ZERO` + the two actors + a couple of arbitrary EOAs.
ADDRESS_ARG_POOL = [
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dEaD",
    "0x00000000000000000000000000000000DeaDBeef",
    "0xBEEF000000000000000000000000000000000000",
]


class CircularSet[T]:
    """Bounded insertion-ordered set with rotate-to-head sampling.

    Direct port of upstream `CircularSet`: `add` moves an existing value to the
    back; `head_and_rotate` returns the back element then rotates so repeated calls
    cycle through the buffer (LRU-ish coverage of seeds)."""

    def __init__(self, set_size: int = MAX_RING_BUFFER_LENGTH,
                 initial_set: Iterable[T] | None = None) -> None:
        self._q: collections.deque[T] = collections.deque(maxlen=set_size)
        if initial_set:
            self._q.extend(initial_set)

    @property
    def empty(self) -> bool:
        return len(self._q) == 0

    def add(self, value: T) -> None:
        if value in self._q:
            self._q.remove(value)
        self._q.append(value)

    def head_and_rotate(self) -> T:
        value = self._q[-1]
        self._q.rotate(1)
        return value


@dataclass
class Tx:
    """One transaction gene. Renders to our harness call `[name, args, value, caller]`."""
    fn: str
    args: list[Any] = field(default_factory=list)
    value: int = 0
    caller: str = "attacker_address"

    def to_call(self) -> list:
        return [self.fn, list(self.args), int(self.value), self.caller]

    def clone(self) -> "Tx":
        return Tx(self.fn, list(self.args), self.value, self.caller)


class Generator:
    """ABI-driven individual generator (port of FinanceFuzz `Generator`)."""

    def __init__(
        self,
        contract_abi: list[dict],
        *,
        callers: list[str] | None = None,
        initial_balance_native: int = 10,
    ) -> None:
        self.callers = list(callers or DEFAULT_CALLERS)
        self.initial_balance_wei = int(initial_balance_native) * 10**18

        # interface: fn_name -> [arg_type, ...]; track payable set for amount seeding.
        self.interface: dict[str, list[str]] = {}
        self._payable: set[str] = set()
        # Class A: exclude tuple-typed (interface-uncallable) functions so the GA
        # never selects one → no "Member not found" compile error (pool==interface).
        for item in interface_eligible(contract_abi):
            if item.get("type") != "function":
                continue
            name = item.get("name")
            if not name:
                continue
            self.interface[name] = [self._canonical_type(i) for i in item.get("inputs", [])]
            if item.get("stateMutability") == "payable":
                self._payable.add(name)

        # Function rotation buffer (upstream function_circular_buffer).
        self._fn_buffer = CircularSet[str](
            set_size=max(1, len(self.interface)), initial_set=list(self.interface),
        )

        # Per-(function, arg_index) value pools + per-function amount pools, refilled
        # from observed/seed values (upstream arguments_pool / amounts_pool).
        self.arguments_pool: dict[str, dict[int, CircularSet]] = {}
        self.amounts_pool: dict[str, CircularSet[int]] = {}

    # ── ABI helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _canonical_type(inp: dict) -> str:
        """Flatten an ABI input to a canonical Solidity type string (tuples → not
        supported by the simple sampler; fall back to the raw type)."""
        t = inp.get("type", "")
        return t

    @property
    def function_names(self) -> list[str]:
        return list(self.interface)

    def get_random_function(self) -> str:
        fn = self._fn_buffer.head_and_rotate()
        return fn

    # ── Individual generation ───────────────────────────────────────────────────

    def generate_random_individual(self, max_length: int = 1) -> list[Tx]:
        """Generate a fresh individual of 1..max_length transactions.

        Upstream `generate_random_individual` emits a single tx; the GA grows length
        through crossover (concatenation). We allow a small initial length so seeds
        already contain short sequences (helps multi-tx bugs surface early)."""
        n = 1 if max_length <= 1 else random.randint(1, max_length)
        return [self._random_tx() for _ in range(n)]

    def _random_tx(self) -> Tx:
        fn = self.get_random_function()
        arg_types = self.interface.get(fn, [])
        args = [self.get_random_argument(t, fn, i) for i, t in enumerate(arg_types)]
        return Tx(fn=fn, args=args, value=self.amount_for(fn),
                  caller=self.get_random_account())

    def amount_for(self, function: str) -> int:
        """msg.value for a call — 0 for non-payable functions (avoids reverts /
        ignored-value noise), a pool value for payable ones."""
        return self.get_random_amount(function) if function in self._payable else 0

    # ── Accounts / amounts ──────────────────────────────────────────────────────

    def get_random_account(self) -> str:
        return random.choice(self.callers)

    def get_random_amount(self, function: str) -> int:
        if function in self.amounts_pool and not self.amounts_pool[function].empty:
            return self.amounts_pool[function].head_and_rotate()
        # Seed the pool: upstream uses {0, 1}; for payable functions add a fundable
        # value so ETH-dependent paths (deposit/claim) are reachable on forge.
        pool = self.amounts_pool.setdefault(function, CircularSet())
        base = random.randint(0, 1)
        pool.add(base)
        pool.add(1 - base)
        if function in self._payable:
            pool.add(self.initial_balance_wei // 10)  # 1 ether at default balance 10
            pool.add(1)
            return self.initial_balance_wei // 10
        return base

    def add_amount_to_pool(self, function: str, amount: int) -> None:
        self.amounts_pool.setdefault(function, CircularSet()).add(int(amount))

    # ── Arguments ─────────────────────────────────────────────────────────────

    def add_argument_to_pool(self, function: str, index: int, value: Any) -> None:
        if isinstance(value, list):
            for v in value:
                self.add_argument_to_pool(function, index, v)
            return
        self.arguments_pool.setdefault(function, {}).setdefault(index, CircularSet()).add(value)

    def _pool_value(self, function: str, index: int) -> Any | None:
        pool = self.arguments_pool.get(function, {}).get(index)
        if pool is not None and not pool.empty:
            return pool.head_and_rotate()
        return None

    def get_random_argument(self, sol_type: str, function: str, index: int) -> Any:
        """Boundary-aware random value for one ABI arg (port of upstream logic)."""
        is_array = "[" in sol_type and "]" in sol_type
        base = sol_type.split("[")[0]

        if is_array:
            size = self._array_size(sol_type)
            return [self._scalar(base, function, index) for _ in range(size)]
        return self._scalar(base, function, index)

    def _array_size(self, sol_type: str) -> int:
        # Only the innermost dimension is sampled; fixed sizes are honoured.
        import re
        dims = re.findall(r"\[(.*?)\]", sol_type)
        inner = dims[0] if dims else ""
        if inner == "":
            return random.randint(0, MAX_ARRAY_LENGTH)
        try:
            return int(inner)
        except ValueError:
            return random.randint(0, MAX_ARRAY_LENGTH)

    def _scalar(self, base: str, function: str, index: int) -> Any:
        pooled = self._pool_value(function, index)
        if pooled is not None:
            return pooled

        if base.startswith("uint"):
            nbytes = self._int_bytes(base, "uint")
            return self.get_random_unsigned_integer(0, UINT_MAX[nbytes])
        if base.startswith("int"):
            nbytes = self._int_bytes(base, "int")
            return self.get_random_signed_integer(INT_MIN[nbytes], INT_MAX[nbytes])
        if base.startswith("bool"):
            return random.randint(0, 1) == 1
        if base.startswith("address"):
            return random.choice(ADDRESS_ARG_POOL)
        if base == "string":
            return random.choice(["", "A", "A" * 32, "A" * 33])
        if base.startswith("bytes"):
            # bytesN (fixed) or dynamic bytes → hex string our harness accepts.
            n = base[len("bytes"):]
            length = int(n) if n.isdigit() else random.randint(0, MAX_ARRAY_LENGTH)
            return "0x" + ("".join(random.choice("0123456789abcdef") for _ in range(length * 2)) or "")
        # Unknown / tuple — emit 0 (best effort; the harness try/catch tolerates a revert).
        return 0

    @staticmethod
    def _int_bytes(base: str, prefix: str) -> int:
        digits = base[len(prefix):]
        bits = int(digits) if digits else 256
        return max(1, min(32, bits // 8))

    @staticmethod
    def get_random_unsigned_integer(lo: int, hi: int) -> int:
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([lo, lo + 1, lo + 2])
        if seed == 1:
            return random.choice([hi, hi - 1, hi - 2])
        return random.randint(lo, hi)

    @staticmethod
    def get_random_signed_integer(lo: int, hi: int) -> int:
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([0, -1, lo, lo + 1])
        if seed == 1:
            return random.choice([0, 1, hi, hi - 1])
        return random.randint(lo, hi)
