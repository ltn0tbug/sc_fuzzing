"""RandomFuzz argument + sequence generation — true uniform randomness.

Ports the reference RandomFuzz sampler (`ref/rlf/.../fuzzers/random/policy_random.py`):
full-range integers, ascii strings, random-length bytes, arrays over the base
type. Per the locked decision, addresses are fully random `uint160` literals (no
alias pool) and reentrancy is a uniform member of the selectable-function pool
(no fixed budget) rather than a force-injected 0.25 head.
"""

from __future__ import annotations

import random
import re

from ...fuzzer.arg_sampling import (
    build_payable_value,
    build_reentry_setup_call,
    coerce_scalar,
    rand_uint160_hex,
)
from ...fuzzer.sol_interface import interface_eligible

# Sentinel marking the "arm the attacker reentrancy harness" choice in the pool.
_REENTRY = object()


def _rand_arg(sol_type: str):
    """Return a uniformly random value of the right shape for `sol_type`.

    Full-range integers (masked to bit width); addresses as random uint160 hex;
    bytes/bytesN as 0x hex; string as ascii; arrays as a list over the base type.
    The scalar draw is already width-correct, then passed through the shared
    Tier-1 `coerce_scalar` so all generators share one encoding path (uint → 0x-hex,
    int → decimal; Tier-2 `_normalize_arg` renders both as decimal Solidity).
    """
    t = sol_type.strip()

    # Arrays: T[] (dynamic, ref SliceTy length 1..15) or T[N] (fixed).
    if t.endswith("]") and "[" in t:
        base = t[: t.rindex("[")]
        size_str = t[t.rindex("[") + 1 : -1]
        if size_str.isdigit():
            n = int(size_str)
        else:
            n = random.randint(1, 15)
        return [_rand_arg(base) for _ in range(n)]

    if t.startswith("uint"):
        size = int(t[4:]) if t[4:].isdigit() else 256
        raw = random.getrandbits(size)                 # full range [0, 2**size)
    elif t.startswith("int"):
        size = int(t[3:]) if t[3:].isdigit() else 256
        p = 1 << (size - 1)
        raw = random.randint(-p, p - 1)                # full signed range
    elif t == "bool":
        raw = random.choice([True, False])
    elif t in ("address", "address payable"):
        raw = rand_uint160_hex()                       # pure random, no alias
    elif t == "string":
        n = random.randint(0, 40)
        raw = bytes(random.randint(1, 127) for _ in range(n)).decode("ascii")
    elif t == "bytes":
        n = random.randint(1, 15)
        raw = "0x" + bytes(random.randint(0, 255) for _ in range(n)).hex()
    elif re.fullmatch(r"bytes(\d+)", t):
        n = int(t[5:])
        raw = "0x" + bytes(random.randint(0, 255) for _ in range(n)).hex()
    else:
        raw = random.getrandbits(256)                  # unknown → full-range uint256

    return coerce_scalar(t, raw)


def _build_call(fn: dict, initial_balance_native: int) -> list:
    arg_types = [inp.get("type", "") for inp in fn.get("inputs", [])]
    args = [_rand_arg(t) for t in arg_types]
    is_payable = fn.get("stateMutability") == "payable"
    value_wei = build_payable_value(is_payable, initial_balance_native)
    return [fn["name"], args, value_wei, "attacker_address"]


def pure_random_fuzz_input(
    abi: list[dict],
    max_calls: int,
    initial_balance_native: int,
    mode: str = "inline",
) -> dict:
    """Build a fully-random fuzz input for RandomFuzz.

    A length-L sequence (L uniform in [1, max_calls]) of calls, each a uniform
    draw over the selectable pool = ABI functions + the reentrancy sentinel. If
    the sentinel is drawn, one `atk.setReentrantCall` entry is hoisted to the
    sequence head and at least one regular call is guaranteed to follow so the
    callback actually fires. `mode` is accepted for signature parity with the
    other generators; RandomFuzz uses no alias pool so it does not affect output.
    """
    _ = mode
    # Class A: only interface-callable functions (tuple-typed ones are dropped).
    functions = [f for f in interface_eligible(abi) if f.get("type") == "function"]
    if not functions:
        return {"calls": [], "description": "random: empty ABI"}

    pool: list = list(functions) + [_REENTRY]
    L = random.randint(1, max(1, max_calls))

    saw_reentry = False
    regular: list = []
    for _ in range(L):
        pick = random.choice(pool)
        if pick is _REENTRY:
            saw_reentry = True
        else:
            regular.append(_build_call(pick, initial_balance_native))

    if saw_reentry:
        target = random.choice(functions)
        target_types = [inp.get("type", "") for inp in target.get("inputs", [])]
        setup = build_reentry_setup_call(target["name"], target_types, _rand_arg)
        if not regular:
            regular.append(_build_call(random.choice(functions), initial_balance_native))
        calls = [setup] + regular
    else:
        calls = regular

    return {"calls": calls, "description": f"random: L={L}"}
