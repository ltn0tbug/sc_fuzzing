"""Harness-shared argument-sampling primitives.

These are the small, method-agnostic pieces that must agree with foundry.py's
address-alias knowledge and reentrancy-setup format. They sit next to foundry
(the owner of that knowledge) so the `baselines → fuzzer` dependency direction
stays clean.

Method-specific argument generation lives in each method's own package
(`randomfuzz/generator.py`, `rlfuzz/args.py`, `madfuzz/args.py`) or in
`llm/random_gen.py` (sscfuzz's non-LLM random generator). This module holds
only what every one of them shares:

  build_address_pool     — the mode-aware alias/external/random address pool
  build_payable_value    — ETH value sampling for payable calls
  build_reentry_setup_call — the `atk.setReentrantCall` setup-dict builder
  rand_uint160_hex       — a uniformly random 160-bit address literal
"""

from __future__ import annotations

import random
import re
from typing import Callable

from .foundry import MAX_REENTRY_COUNT, FoundryFuzzer

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# Address aliases that render verbatim as in-scope Solidity vars in the generated
# test. Names are sourced from foundry's _ADDR_ALIASES so the two cannot drift.
_ATTACKER = "attacker_address"
_TARGET = "target_address"
_DEPLOYER = "deployer_address"
assert {_ATTACKER, _TARGET, _DEPLOYER} <= FoundryFuzzer._ADDR_ALIASES, (
    "arg_sampling alias names have drifted from FoundryFuzzer._ADDR_ALIASES"
)

# Number of random uint160 literals mixed into every alias pool for diversity.
_N_RANDOM_ADDRS = 2


def rand_uint160_hex() -> str:
    """A uniformly random 160-bit address as a 0x-prefixed 40-hex-char literal.

    foundry.py renders a raw hex address as `address(uint160(<decimal>))`, so any
    value in [0, 2**160) is a valid address argument.
    """
    return "0x" + f"{random.getrandbits(160):040x}"


# ── Width-aware scalar coercion (Tier-1 generator enforcement) ────────────────
# type_width() is the SINGLE place integer widths are parsed. Tier-1
# (coerce_scalar), Tier-2 (foundry._normalize_arg), and the GBNF per-width caps
# (llm.backends._arg_rule) all defer to it, so a width rule can never drift
# between the generator, the renderer, and the grammar. See
# rule/update_arg_rendering.md.

_UINT_RE = re.compile(r"uint(\d*)")
_INT_RE = re.compile(r"int(\d*)")
_BYTESN_RE = re.compile(r"bytes(\d+)")
_HEX_CHARS = set("0123456789abcdefABCDEF")


def type_width(sol_type: str) -> tuple[str, int] | None:
    """Parse a `uintN`/`intN` Solidity type into `(kind, bits)`.

    Returns `("uint"|"int", bits)`, bits defaulting to 256 for bare `uint`/`int`;
    `None` for any non-integer type (including `bytesN`, arrays, address, …).
    This is the ONE place integer widths are parsed.
    """
    t = (sol_type or "").strip()
    m = _UINT_RE.fullmatch(t)
    if m:
        return ("uint", int(m.group(1)) if m.group(1) else 256)
    m = _INT_RE.fullmatch(t)
    if m:
        return ("int", int(m.group(1)) if m.group(1) else 256)
    return None


def parse_int(value) -> int:
    """Parse an int from a Python int/bool or a decimal/hex string. Raises
    ValueError/TypeError on anything unparseable (callers decide the fallback)."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("empty")
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    n = int(s, 16) if s.lower().startswith("0x") else int(s)
    return -n if neg else n


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "0x1")


def bytesN_hex(value, n: int) -> str:
    """Return a 0x-prefixed literal of exactly `2*n` hex chars (left-aligned pad /
    right-truncate) for a `bytesN` slot. Non-hex input degrades to all-zero."""
    s = str(value).strip()
    body = s[2:] if s.lower().startswith("0x") else s
    if not all(c in _HEX_CHARS for c in body):
        body = ""
    body = (body + "0" * (2 * n))[: 2 * n]
    return "0x" + body


def dyn_bytes_hex(value) -> str:
    """Return a 0x-prefixed even-length hex literal for a dynamic `bytes` slot.
    Non-hex input is UTF-8-encoded so the value stays well-formed."""
    s = str(value).strip()
    body = s[2:] if s.lower().startswith("0x") else s
    if not all(c in _HEX_CHARS for c in body):
        body = s.encode("utf-8", "ignore").hex()
    if len(body) % 2:
        body = "0" + body
    return "0x" + body


def coerce_scalar(sol_type: str, value):
    """Tier-1 generator enforcement: return `value` already well-formed and
    in-range for `sol_type`.

      uintN  → 0x-hex masked to N bits
      intN   → decimal string clamped to the signed range
      bytesN → 0x + exactly 2N hex (pad/truncate)
      bytes  → 0x + even hex
      bool   → Python bool
      address/string/unknown → the (already well-formed) value, unchanged

    Generators call this so their OUTPUT is valid by construction; the render
    chokepoint `foundry._normalize_arg` (Tier 2) then only has to render it, and
    its warn+default path becomes a genuine anomaly signal. Never raises.
    """
    t = (sol_type or "").strip()
    w = type_width(t)
    if w is not None:
        kind, bits = w
        try:
            n = parse_int(value)
        except (ValueError, TypeError):
            n = 0
        if kind == "uint":
            return hex(n & ((1 << bits) - 1))
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        return str(max(lo, min(hi, n)))
    m = _BYTESN_RE.fullmatch(t)
    if m:
        return bytesN_hex(value, int(m.group(1)))
    if t == "bool":
        return _as_bool(value)
    if t == "bytes":
        return dyn_bytes_hex(value)
    return value if isinstance(value, str) else str(value)


def build_address_pool(mode: str, external_addrs: list[str] | None = None) -> list[str]:
    """Return the mode-aware address pool used by RLFuzz / MADFuzz / the mutator /
    the sscfuzz random branch.

    Layout (locked with the user):
      inline → [attacker, deployer, target, *externals, zero, *random uint160]
      fork   → [attacker, target, *externals, zero, *random uint160]  (no deployer:
               the attacker never acts as the on-chain deployer in fork mode)

    Alias entries are the verbatim Solidity var names; externals are resolved hex
    strings (foundry casts them to address(uint160(...))). The random literals are
    chosen once per call, so a caller that needs a stable index→address mapping
    (MADFuzz's per-arg address DQN) must build the pool once and reuse it.
    """
    external_addrs = external_addrs or []
    if mode == "fork":
        aliases = [_ATTACKER, _TARGET]
    else:
        aliases = [_ATTACKER, _DEPLOYER, _TARGET]

    pool: list[str] = list(aliases)
    pool.extend(a for a in external_addrs if a)
    pool.append(ZERO_ADDRESS)
    pool.extend(rand_uint160_hex() for _ in range(_N_RANDOM_ADDRS))
    return pool


def build_payable_value(is_payable: bool, initial_balance_native: int) -> int:
    """Sample an ETH value (wei) for a payable call, capped at the test address balance."""
    if not is_payable:
        return 0
    max_wei = max(1, initial_balance_native) * 10**18
    candidates = [0, 1, 10**15, 10**16, 10**17, 10**18, 2 * 10**18, 5 * 10**18]
    candidates = [v for v in candidates if v <= max_wei]
    return random.choice(candidates) if candidates else 0


def build_reentry_setup_call(
    target_fn: str,
    target_arg_types: list[str],
    arg_gen: Callable[[str], object],
    *,
    max_count: int | None = None,
) -> list:
    """Build a `atk.setReentrantCall` entry that re-enters `target_fn`.

    Matches the format consumed by foundry.py::_build_reentrancy_test:
      ["atk.setReentrantCall",
       {"reentrant_func": "fn",
        "reentrant_args": [encoded values],
        "max_count": N},
       "0x0", "attacker_address"]

    `reentrant_func` is the bare function name on the target contract; the
    Solidity signature is reconstructed by FoundryFuzzer from the ABI's input
    types. `target_arg_types` supplies the shapes; `arg_gen(sol_type)` is the
    method's own per-type value generator (random for RandomFuzz/RLFuzz,
    DQN-indexed for MADFuzz). `max_count` is uniform in [1, MAX_REENTRY_COUNT]
    unless overridden — deeper re-entry rarely hits new logic but explodes the
    forge --debug trace.
    """
    reentrant_args = [arg_gen(t) for t in target_arg_types]
    if max_count is None:
        max_count = random.randint(1, MAX_REENTRY_COUNT)
    return [
        "atk.setReentrantCall",
        {
            "reentrant_func": target_fn,
            "reentrant_args": reentrant_args,
            "max_count": int(max_count),
        },
        "0x0",
        "attacker_address",
    ]
