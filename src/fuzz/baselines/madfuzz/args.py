"""MADFuzz per-type action spaces + decoders.

Ports the reference per-type DQN design
(`ref/madfuzz/.../fuzzers/reinforcement/policy_reinforcement_drqn.py`):

  uint  → 257 actions; action a → 0 (a=0) else randint(2^(a-1), 2^a-1)
  int   → 255 actions; action a → a value in the segment [shift_table[2a], shift_table[2a+2])
  bool  → 2 actions;   action a → bool(a)
  bytes → 256 actions PER BYTE; a byte sequence records one action per position
  addr  → len(addr_pool) actions; action a → addr_pool[a]
  string → no DQN (pure random ascii)

Each per-type DQN outputs an index; the decoders here turn that index into a
concrete value. Arrays are sampled as a single element of their base type (the
harness renders a length-1 array), matching the pre-rewrite behavior.
"""

from __future__ import annotations

import random

UINT_ACTIONS = 257
INT_ACTIONS = 255
BOOL_ACTIONS = 2
BYTE_ACTIONS = 256

# Fixed per-type action dims (addr is len(addr_pool), supplied by the policy).
ACTION_DIMS: dict[str, int] = {
    "uint": UINT_ACTIONS,
    "int": INT_ACTIONS,
    "bool": BOOL_ACTIONS,
    "bytes": BYTE_ACTIONS,
}


def bucket_of(sol_type: str) -> str:
    """Route a Solidity type to a per-type DQN bucket.

    Array types are stripped to their base element type (sampled as a length-1
    array). `string` is its own bucket (pure random, no DQN).
    """
    t = sol_type.strip()
    if t.endswith("]") and "[" in t:
        t = t[: t.rindex("[")].strip()
    if t.startswith("uint"):
        return "uint"
    if t.startswith("int"):
        return "int"
    if t == "bool":
        return "bool"
    if t in ("address", "address payable"):
        return "addr"
    if t == "string":
        return "string"
    if t.startswith("bytes"):
        return "bytes"
    return "uint"


def type_bit_size(sol_type: str, default: int = 256) -> int:
    """Bit width for a uint*/int* type (256 for bare uint/int)."""
    t = sol_type.strip()
    if t.endswith("]") and "[" in t:
        t = t[: t.rindex("[")].strip()
    if t.startswith("uint"):
        return int(t[4:]) if t[4:].isdigit() else 256
    if t.startswith("int"):
        return int(t[3:]) if t[3:].isdigit() else 256
    return default


def byte_len(sol_type: str) -> int:
    """Number of bytes to emit for a bytes/bytesN type (dynamic → random 1..32)."""
    t = sol_type.strip()
    if t.endswith("]") and "[" in t:
        t = t[: t.rindex("[")].strip()
    if t == "bytes":
        return random.randint(1, 32)
    if t.startswith("bytes") and t[5:].isdigit():
        return int(t[5:])
    return random.randint(1, 32)


def decode_uint(action: int, size: int = 256) -> int:
    """action → 0 (a=0) else a uniform value in [2^(a-1), 2^a-1]. Masked to `size`."""
    a = int(action) % (size + 1)
    if a == 0:
        return 0
    return random.randint(1 << (a - 1), (1 << a) - 1)


def decode_int(action: int, size: int = 256) -> int:
    """action → a value in the signed segment picked by the shift table (ref logic)."""
    a = int(action) % max(1, size - 1)
    shift_table = list(range(-size + 1, size))
    shift_1 = shift_table[a * 2]
    shift_2 = shift_table[a * 2 + 2]
    rand_1 = (1 << shift_1) if shift_1 > 0 else -(1 << (-shift_1))
    rand_2 = (1 << shift_2) if shift_2 > 0 else -(1 << (-shift_2))
    return random.randint(rand_1, rand_2 - 1)


def decode_bool(action: int) -> bool:
    return bool(int(action) % 2)


def decode_byte_seq(actions: list[int]) -> str:
    """Per-byte actions → a 0x-hex bytes literal (each action is one byte)."""
    return "0x" + bytes(int(a) % 256 for a in actions).hex()


def random_string() -> str:
    """Pure-random ascii string (no DQN), matching ref's _select_string."""
    n = random.randint(0, 40)
    return bytes(random.randint(1, 127) for _ in range(n)).decode("ascii")
