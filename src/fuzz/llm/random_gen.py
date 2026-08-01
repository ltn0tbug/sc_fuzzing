"""sscfuzz's non-LLM random input generator (boundary-value pools).

This is NOT a research baseline — it is sscfuzz's own fallback / ε-greedy
random-generation branch:
  - the ε-greedy random-generation branch in orchestrator.py, and
  - the LLM-exhausted fallback in llm/generator.py.

It draws numeric/bytes args from curated boundary-value pools (uint/int/bool/
bytes) and addresses from the mode-aware pool built by
`fuzzer.arg_sampling.build_address_pool`. Callers pass the pool they want; when
none is given, an inline pool with no externals is synthesized as a safe default.

RandomFuzz used to reuse this module (via baselines/common/args.py). It no longer
does — RandomFuzz has its own pure-random generator (randomfuzz/generator.py) —
so this generator is purely a sscfuzz concern and lives next to the generator.
"""

from __future__ import annotations

import random
from typing import Any

from ..fuzzer.arg_sampling import (
    build_address_pool,
    build_payable_value,
    build_reentry_setup_call,
    coerce_scalar,
)
from ..fuzzer.sol_interface import interface_eligible

# Uint candidate values: 0, small ints, powers of 2 boundaries, fee/ETH amounts, uint256 max
_UINT_VALUES: list[int] = (
    [0, 1, 2, 3, 5, 7, 10, 16, 17, 32, 33, 50, 64, 100, 127, 128, 255, 256, 1000]
    + [2**8 - 1, 2**8, 2**16 - 1, 2**16, 2**32 - 1, 2**32, 2**64 - 1, 2**64]
    + [2**128 - 1, 2**128, 2**160 - 1, 2**192, 2**224, 2**255 - 1, 2**255, 2**256 - 1]
    + [10**i for i in range(2, 25)]            # decimal-scale amounts up to 1e24
    + [i * 10**18 for i in range(1, 21)]       # 1..20 ETH expressed in wei
)
_UINT_VALUES = list(dict.fromkeys(_UINT_VALUES))  # dedupe, preserve order

# Int candidate values: positive ints, negatives, signed boundaries
_INT_VALUES: list[int] = (
    [0, 1, -1, 2, -2, 10, -10, 100, -100, 1000, -1000]
    + [2**8 - 1, -(2**8), 2**16 - 1, -(2**16), 2**32 - 1, -(2**32)]
    + [2**64 - 1, -(2**64), 2**127 - 1, -(2**127), 2**255 - 1, -(2**255)]
)
_INT_VALUES = list(dict.fromkeys(_INT_VALUES))

_BOOL_VALUES: list[bool] = [True, False]

# Byte pool: small byte strings (bytesN slots are padded to width by coerce_scalar)
_BYTE_VALUES: list[str] = [
    "0x",
    "0x00",
    "0xff",
    "0xdeadbeef",
    "0xcafebabe",
] + [f"0x{i:02x}" for i in range(256)]

# String pool: short ascii literals. String slots get their own bucket (they used
# to route through `bytes`, which produced hex-shaped junk strings).
_STRING_VALUES: list[str] = ["", "a", "test", "hello", "0", "1", "owner", "admin"]


def _bucket(sol_type: str) -> str:
    """Map a Solidity type string to a pool key."""
    t = sol_type.strip()
    if not t:
        return "uint"
    if t.startswith("uint"):
        return "uint"
    if t.startswith("int"):
        return "int"
    if t == "address" or t.startswith("address"):
        return "addr"
    if t == "bool":
        return "bool"
    if t == "string":
        return "string"
    if t.startswith("bytes"):
        return "bytes"
    if t.endswith("[]") or "[" in t:
        return _bucket(t.split("[", 1)[0])
    return "uint"  # fallback


def random_arg_for_type(sol_type: str, address_pool: list[str]) -> Any:
    """Sample a single random value of the right shape for `sol_type`.

    The raw draw comes from the boundary-value pool for the slot's family; the
    value is then passed through `coerce_scalar` (Tier-1) so it is masked/padded
    to the slot's real WIDTH (uint16 stays a real uint16, bytes32 is full-width) —
    not the width-collapsed junk the old `_encode_scalar` produced. Addresses are
    drawn from `address_pool` (aliases render verbatim, hex literals are cast by
    foundry). Array types wrap a single element of the base type.
    """
    scalar_type = sol_type.split("[", 1)[0].strip() if "[" in sol_type else sol_type.strip()
    bucket = _bucket(scalar_type)
    if bucket == "addr":
        val: Any = random.choice(address_pool) if address_pool else "attacker_address"
    elif bucket == "uint":
        val = random.choice(_UINT_VALUES)
    elif bucket == "int":
        val = random.choice(_INT_VALUES)
    elif bucket == "bool":
        val = random.choice(_BOOL_VALUES)
    elif bucket == "string":
        val = random.choice(_STRING_VALUES)
    else:  # bytes / bytesN
        val = random.choice(_BYTE_VALUES)

    encoded = coerce_scalar(scalar_type, val)
    if sol_type.endswith("[]") or ("[" in sol_type and "]" in sol_type):
        return [encoded]
    return encoded


def build_call(
    fn_name: str,
    arg_types: list[str],
    is_payable: bool,
    caller_pool: list[str],
    initial_balance_native: int,
    address_pool: list[str],
) -> list:
    """Build one [fn, args, value_wei, caller] entry with random boundary args."""
    args = [random_arg_for_type(t, address_pool) for t in arg_types]
    value_wei = build_payable_value(is_payable, initial_balance_native)
    caller = random.choice(caller_pool) if caller_pool else "attacker_address"
    return [fn_name, args, value_wei, caller]


def random_fuzz_input(
    abi: list[dict],
    max_calls: int,
    initial_balance_native: int,
    *,
    address_pool: list[str] | None = None,
    reentrancy_prob: float = 0.2,
) -> dict:
    """Build a fully-random fuzz input by uniform ABI sampling.

    Used by sscfuzz's ε-greedy random-input branch and the LLM-exhausted
    fallback. Steps:

      1. Pick random sequence length L in [1, max_calls].
      2. With probability `reentrancy_prob`, prepend a `atk.setReentrantCall`
         entry targeting a random ABI function.
      3. For each remaining slot: pick a random ABI function, build a call entry
         with random boundary args and a random payable value.

    `address_pool` supplies the mode-aware address pool (see
    fuzzer.arg_sampling.build_address_pool); when None, an inline pool with no
    externals is synthesized. Returns a FuzzInput-shaped dict.
    """
    if address_pool is None:
        address_pool = build_address_pool("inline")

    # Class A: only interface-callable functions (tuple-typed ones are dropped).
    functions = [f for f in interface_eligible(abi) if f.get("type") == "function"]
    if not functions:
        return {"calls": [], "description": "random: empty ABI"}

    L = random.randint(1, max(1, max_calls))
    calls: list = []
    caller_pool = ["attacker_address"]

    # Optional reentrancy setup head.
    if random.random() < reentrancy_prob:
        target = random.choice(functions)
        target_types = [inp.get("type", "") for inp in target.get("inputs", [])]
        calls.append(build_reentry_setup_call(
            target["name"], target_types,
            lambda t: random_arg_for_type(t, address_pool),
        ))
        L = max(1, L - 1)

    for _ in range(L):
        fn = random.choice(functions)
        arg_types = [inp.get("type", "") for inp in fn.get("inputs", [])]
        is_payable = fn.get("stateMutability") == "payable"
        calls.append(build_call(
            fn["name"], arg_types, is_payable, caller_pool,
            initial_balance_native, address_pool,
        ))

    return {"calls": calls, "description": f"random: L={L} (ε-greedy)"}
