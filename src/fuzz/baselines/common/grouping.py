"""ABI-based function classification used by RLFuzz and MADFuzz.

Both RLFuzz and MADFuzz use the same 5 groups based on opcode patterns in the
compiled bytecode:
  pay-call, nopay-call, pay-nocall, nopay-nocall-store, selfdestruct

(The reference MADFuzz carries an extra "status" view/pure group; we drop it here
so MADFuzz's function selection matches RLFuzz — both use RLFUZZ_GROUPS.)

We approximate the opcode-level classification from Solidity source + ABI metadata,
since Foundry executes via the JSON test runner (no opcode tracing). The mapping:

  payable        ← ABI stateMutability == "payable"
  has_call       ← source contains .call(, call{, delegatecall, staticcall
  has_store      ← source contains assignment to a state variable (heuristic: any
                    non-view/pure function with a body that contains "=")
  has_selfdestruct ← source contains "selfdestruct"
  is_view        ← stateMutability in {view, pure}

This is intentionally lightweight — see baselines/README for the rationale.
"""

from __future__ import annotations

import re

from ...fuzzer.sol_interface import interface_eligible

# RLFuzz: 5-group classification (paper Table) + "attacker" group (our extension).
#
# The "attacker" group covers functions on the unified Attacker
# contract (declared in inline.sol.tpl), not on the contract-under-test.
# The original papers do not model an attacker harness — neither RLFuzz nor
# MADFuzz can exploit reentrancy as a result (see research.md §14.7). We add
# this group so both baselines can also drive setReentrantCall.
ATTACKER_GROUP: str = "attacker"
ATTACKER_FUNCTIONS: list[str] = ["atk.setReentrantCall"]

RLFUZZ_GROUPS: list[str] = [
    "pay-call",              # 0
    "nopay-call",            # 1
    "pay-nocall",            # 2
    "nopay-nocall-store",    # 3
    "selfdestruct",          # 4
    ATTACKER_GROUP,          # 5  (our extension — attacker contract harness)
]

# MADFuzz uses the identical grouping (the reference "status" view/pure group is
# dropped so its function selection matches RLFuzz). Kept as a named alias so
# call sites/read as method-specific.
MADFUZZ_GROUPS: list[str] = RLFUZZ_GROUPS


_CALL_PATTERNS = (".call(", "call{", "delegatecall", "staticcall", ".transfer(", ".send(")
_SELFDESTRUCT_PATTERN = "selfdestruct"


def _extract_function_body(source: str, fn_name: str) -> str:
    """Return the body of function `fn_name`, or '' if not found.

    Heuristic only — handles standard `function NAME(...) ... { ... }` declarations.
    Multi-line declarations and inheritance overrides may shorten the captured body
    but that is acceptable for group classification (we only check for substring patterns).
    """
    pattern = re.compile(
        r"function\s+" + re.escape(fn_name) + r"\s*\(",
        re.MULTILINE,
    )
    m = pattern.search(source)
    if not m:
        return ""

    # Find the opening brace and matching closing brace.
    start = source.find("{", m.end())
    if start < 0:
        return ""

    depth = 0
    for i in range(start, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1 : i]
    return source[start + 1 :]


def _classify_one(
    fn_name: str,
    abi_item: dict,
    source: str,
) -> str:
    """Return the group name for a single function."""
    mutability = abi_item.get("stateMutability", "nonpayable")
    is_view = mutability in ("view", "pure")
    is_payable = mutability == "payable"

    body = _extract_function_body(source, fn_name)
    has_call = any(p in body for p in _CALL_PATTERNS)
    has_selfdestruct = _SELFDESTRUCT_PATTERN in body
    # Rough "store" heuristic: any non-view function that does anything substantial
    # is likely writing storage. Fall through to nopay-nocall-store as the catch-all.
    has_store = (not is_view) and ("=" in body or len(body.strip()) > 0)

    if has_selfdestruct:
        return "selfdestruct"
    if is_payable:
        return "pay-call" if has_call else "pay-nocall"
    if has_call:
        return "nopay-call"
    if has_store:
        return "nopay-nocall-store"
    # Last resort — view/pure + uncategorized functions bucket into nopay-nocall-store
    # (no separate "status" group; both RLFuzz and MADFuzz share RLFUZZ_GROUPS).
    return "nopay-nocall-store"


def classify_functions(
    abi: list[dict],
    source: str,
    *,
    groups: list[str] = RLFUZZ_GROUPS,
) -> tuple[dict[int, list[str]], dict[str, int]]:
    """Classify ABI functions into `groups`.

    Returns:
      group_to_fns — {group_index: [fn_name, ...]} for every group index
      fn_to_group  — {fn_name: group_index} for every function

    Empty groups are kept (RL action masking uses these — empty groups are masked).
    """
    group_to_fns: dict[int, list[str]] = {i: [] for i in range(len(groups))}
    fn_to_group: dict[str, int] = {}

    # Class A: RLFuzz/MADFuzz select functions from these groups, so tuple-typed
    # (interface-uncallable) functions must be excluded here too.
    for item in interface_eligible(abi):
        if item.get("type") != "function":
            continue
        name = item.get("name", "")
        if not name:
            continue
        group_name = _classify_one(name, item, source)
        try:
            idx = groups.index(group_name)
        except ValueError:
            # Group not in the active set — bucket into the catch-all
            idx = groups.index("nopay-nocall-store")
        group_to_fns[idx].append(name)
        fn_to_group[name] = idx

    # Attacker group is always populated with the synthetic harness functions
    # (currently just setReentrantCall). These are not in the contract ABI;
    # they live on the unified Attacker test contract.
    if ATTACKER_GROUP in groups:
        idx = groups.index(ATTACKER_GROUP)
        group_to_fns[idx] = list(ATTACKER_FUNCTIONS)
        for fn in ATTACKER_FUNCTIONS:
            fn_to_group[fn] = idx

    return group_to_fns, fn_to_group
