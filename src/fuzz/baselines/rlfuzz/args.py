"""RLFuzz argument generation — ported from the reference seed-value scheme.

Reference: `ref/rlf/.../fuzzers/reinforcement/policy_reinforcement.py`
(`_select_int` / `_select_uint`) + the seed tables in
`ref/rlf/.../fuzzers/seed/{int_values,amounts}.py`.

Integers are drawn 90% from a small frequent-value table, 8% from a larger
unfrequent-value table, and 2% uniformly over the full bit range, then masked to
the argument's bit width. Payable values are drawn from the ported `AMOUNTS`
table (capped to the test balance). Addresses come from the caller-supplied
mode-aware pool (fuzzer.arg_sampling.build_address_pool).
"""

from __future__ import annotations

import random
import re

# ── Ported reference seed tables ──────────────────────────────────────────────

INT_VALUES_FREQUENT: list[int] = [
    0x0,
    0x1,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    0x8,
    0x2,
    0x4,
    0x3,
]

INT_VALUES_UNFREQUENT: list[int] = [
    0x5, 0x9, 0x10, 0x20, 0x6,
    0x8000000000000000000000000000000000000000000000000000000000000000,
    0x400000000000000000000, 0x1000000000000000000000, 0x2000, 0x80,
    0x4000000000000000000000, 0x800000, 0x40, 0x10000, 0x400, 0x4000000,
    0x200000000, 0x800000000000000000000, 0x1000000, 0x20000000, 0x40000,
    0x20000, 0x20000000000000000000000, 0x4000000000000, 0x200, 0x80000,
    0x8000000000000000000000, 0x8000, 0x800, 0x1000, 0x80000000000,
    0x2000000000000000000000, 0x8000000, 1000000000000000000000000001,
    0x4000000000000000000, 0x100000000, 0x200000000000000000000,
    0x800000000000, 0x80000000, 0x1000000000, 0x100, 0x80000000000000,
    0x200000000000,
]

AMOUNTS: list[int] = [
    99999999999999999999999999999, 0x0, 0x1, 0x1000000000000000000000000,
    0x30000000000000, 1000000000000000000, 0x180000000000000, 100000000000000000,
    10000000000000000, 1000000000000000, 0x2, 5000000000000000, 0x20,
    0x700000000000000, 0x8, 0x3c00000000000, 0xe00000000000000,
    0x400000000000000000000000, 50000000000000000, 500000000000000000,
    0x18000000000000, 0x3, 0x80, 0x300000000000000, 0x1000000000000000000000001,
    5000000000000000000, 0x1c00000000000000, 0x4, 10000000000000000000,
    0xc000000000000, 0x2000, 20000000000000000, 0x40, 200000000000000000,
    2000000000000000, 0x800000000000000000000, 0x800000000000000000000000,
    0x1000000000000000000000002, 0x400, 0x80000000000000, 0x100000000000000,
    0xc00000000000, 0x1800000000000000000, 0x800000000000000000,
    0x70000000000000, 250000000000000, 0x380000000000000, 0x8000000000000000000,
    0x8000000000000000, 0x1000,
]


# ── Reference integer selectors (masked to bit size) ──────────────────────────

def _select_uint(size: int) -> int:
    s = random.random()
    if s < 0.9:
        value = random.choice(INT_VALUES_FREQUENT)
    elif s < 0.98:
        value = random.choice(INT_VALUES_UNFREQUENT)
    else:
        return random.randint(0, (1 << size) - 1)
    return value & ((1 << size) - 1)


def _select_int(size: int) -> int:
    s = random.random()
    if s < 0.9:
        value = random.choice(INT_VALUES_FREQUENT)
    elif s < 0.98:
        value = random.choice(INT_VALUES_UNFREQUENT)
    else:
        p = 1 << (size - 1)
        return random.randint(-p, p - 1)
    value &= (1 << size) - 1
    if value & (1 << (size - 1)):          # two's-complement sign extension
        value -= 1 << size
    return value


def rlfuzz_arg_for_type(sol_type: str, addr_pool: list[str], slice_size: int | None = None):
    """Return a random value of the right shape for `sol_type` (RLFuzz scheme).

    `addr_pool` is the mode-aware address pool; `slice_size` sets the length of
    dynamic arrays (ref's per-tx slice size, uniform in [1,5] or None → [1,15]).
    """
    t = sol_type.strip()

    if t.endswith("]") and "[" in t:
        base = t[: t.rindex("[")]
        size_str = t[t.rindex("[") + 1 : -1]
        if size_str.isdigit():
            n = int(size_str)
        else:
            n = slice_size if slice_size is not None else random.randint(1, 15)
        return [rlfuzz_arg_for_type(base, addr_pool, slice_size) for _ in range(n)]

    if t.startswith("uint"):
        size = int(t[4:]) if t[4:].isdigit() else 256
        return str(_select_uint(size))
    if t.startswith("int"):
        size = int(t[3:]) if t[3:].isdigit() else 256
        return str(_select_int(size))
    if t == "bool":
        return random.choice([True, False])
    if t in ("address", "address payable"):
        return random.choice(addr_pool) if addr_pool else "attacker_address"
    if t == "string":
        n = random.randint(0, 40)
        return bytes(random.randint(1, 127) for _ in range(n)).decode("ascii")
    if t == "bytes":
        n = random.randint(1, 15)
        return "0x" + bytes(random.randint(0, 255) for _ in range(n)).hex()
    m = re.fullmatch(r"bytes(\d+)", t)
    if m:
        n = int(m.group(1))
        return "0x" + bytes(random.randint(0, 255) for _ in range(n)).hex()

    return str(_select_uint(256))


def rlfuzz_payable_value(is_payable: bool, initial_balance_native: int) -> int:
    """Sample an ETH value (wei) from the ported AMOUNTS table, capped to balance."""
    if not is_payable:
        return 0
    max_wei = max(1, initial_balance_native) * 10**18
    candidates = [v for v in AMOUNTS if v <= max_wei]
    return random.choice(candidates) if candidates else 0
