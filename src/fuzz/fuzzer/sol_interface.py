"""ABI → Solidity text helpers + pragma detection — the "turn an ABI into Solidity"
job, split out of `foundry.py`.

Every function here is pure (no `FoundryFuzzer` state): given an ABI / source
string it returns Solidity text or a mode string. `foundry.py` imports these back
and re-exports them, so `from .foundry import _abi_to_interface` etc. still work.
"""

import random
import re

# ── ABI → Solidity interface generator (used by legacy-pragma mode) ───────────
# When the contract under test uses Solidity <0.8 we cannot import its source
# into our 0.8 test file. Instead we declare an `interface I<Name> { ... }` in
# the test, derived from the ABI, and deploy the contract via `vm.getCode` +
# assembly `create`. The interface provides the typed handle for calls; the
# bytecode is opaque to the test's compiler.

def _needs_data_location(t: str) -> bool:
    """Return True if `t` is a reference type (needs `memory`/`calldata` in interface)."""
    if t in ("bytes", "string"):
        return True
    if t.startswith("tuple"):
        return True
    if t.endswith("]"):  # any array (`uint256[]`, `address[3]`, etc.)
        return True
    return False


def _expand_abi_type(t: str, components: list[dict] | None) -> str:
    """Expand ABI type to Solidity. Tuples → `(T,U,V)` with the same array suffix."""
    if t.startswith("tuple") and components:
        inner = ",".join(
            _expand_abi_type(c.get("type", ""), c.get("components"))
            for c in components
        )
        suffix = t[len("tuple"):]
        return f"({inner}){suffix}"
    return t


def _format_param(item: dict, *, is_return: bool) -> str:
    """Render one ABI input/output as a Solidity interface parameter."""
    sol_type = _expand_abi_type(item.get("type", ""), item.get("components"))
    if _needs_data_location(item.get("type", "")):
        location = "memory" if is_return else "calldata"
        return f"{sol_type} {location}"
    return sol_type


def interface_eligible(abi: list[dict]) -> list[dict]:
    """Return the ABI with functions the harness can't call filtered out — the
    SINGLE source of truth for the callable action space (pool == interface ==
    grammar).

    A function is dropped iff any of its inputs OR outputs contains a `tuple`
    type: we don't synthesize the `struct` definitions a tuple-typed signature
    needs (see memory tuple-support-deferred). The filter is OVERLOAD-AWARE — each
    overload is a distinct ABI entry, so a tuple overload is dropped while a clean
    overload of the same name survives. Non-function entries (constructor / event /
    error / fallback / receive) pass through unchanged so callers that also read
    those (e.g. constructor synthesis) still see them.

    Apply this at EVERY function-selection site: foundry's `_abi_types` build, the
    mutator's ABI tables, the baseline selectors (randomfuzz / rlfuzz-madfuzz
    grouping), and the GBNF `_build_gbnf` — so no path can select a function the
    interface omits. See rule/update_arg_rendering.md.
    """
    out: list[dict] = []
    for item in abi:
        if item.get("type", "function") != "function":
            out.append(item)
            continue
        if _has_tuple(item.get("inputs", [])) or _has_tuple(item.get("outputs", [])):
            continue
        out.append(item)
    return out


def _abi_to_interface(abi: list[dict], contract_name: str) -> str:
    """Generate a Solidity `interface I<contract_name>` declaration from an ABI."""
    return _render_interface(f"I{contract_name}", abi)


def _render_interface(iface_name: str, abi: list[dict]) -> str:
    """Generate a Solidity interface declaration with an explicit name from an ABI.

    Skips events, errors, constructors, fallback, and receive (none of these
    appear in a Solidity interface body — except fallback/receive which need
    special syntax we don't use for typed external calls).

    Tuple-typed inputs/outputs from real DeFi ABIs would normally require a
    `struct` definition in the interface, which we don't generate. Functions
    whose signature contains any `tuple` type are omitted from the interface
    — the fuzzer can't generate tuple-typed inputs anyway, and excluding such
    functions from the action space is the safe path.
    """
    lines = [f"interface {iface_name} {{"]
    for item in interface_eligible(abi):
        # A minimal hand-authored external ABI may omit "type" (every entry is a
        # function); only skip entries that are explicitly a non-function.
        # Tuple-typed functions are already dropped by interface_eligible (the
        # single source of truth shared with every selection site).
        if item.get("type", "function") != "function":
            continue
        name = item.get("name", "")
        if not name:
            continue
        inputs = [_format_param(i, is_return=False) for i in item.get("inputs", [])]
        outputs = [_format_param(o, is_return=True) for o in item.get("outputs", [])]

        mutability = item.get("stateMutability", "nonpayable")
        mut_kw = ""
        if mutability == "view":
            mut_kw = " view"
        elif mutability == "pure":
            mut_kw = " pure"
        elif mutability == "payable":
            mut_kw = " payable"

        ret = f" returns ({', '.join(outputs)})" if outputs else ""
        lines.append(f"    function {name}({', '.join(inputs)}) external{mut_kw}{ret};")
    lines.append("}")
    return "\n".join(lines)


def _has_tuple(params: list[dict]) -> bool:
    """True if any param (or array thereof) is a tuple type."""
    for p in params:
        t = p.get("type", "")
        # `tuple`, `tuple[]`, `tuple[3]`, `tuple[][2]` — all start with "tuple"
        if t.startswith("tuple"):
            return True
    return False


def _find_constructor_abi(abi: list[dict]) -> dict | None:
    """Return the constructor entry from the ABI, or None if none / no args."""
    for item in abi:
        if item.get("type") == "constructor":
            return item
    return None


# Address aliases an `extend.constructor_args` entry may use for an address-typed
# parameter. Only the EOAs that exist BEFORE the target is deployed are valid —
# target_address doesn't exist yet at constructor time, so referencing it is
# rejected with a clear error.
_CTOR_ADDR_ALIASES: frozenset[str] = frozenset({"deployer_address", "attacker_address"})

# Defaults for synthesizing constructor args at deploy time. SmartBugs has 6
# contracts with required ctor args — we use sentinel non-zero values so
# `require(_owner != 0)` checks don't trip. This is a best-effort fallback;
# contracts with non-trivial ctor preconditions are documented as such.
_CTOR_DEFAULT_PER_TYPE: dict[str, str] = {
    "address": "address(uint160(0xdead))",
    "address payable": "payable(address(uint160(0xdead)))",
    "bool": "true",
    "string": '""',
    "bytes": "hex\"\"",
}


def _solidity_default_for(t: str, components: list[dict] | None) -> str:
    """Pick a Solidity literal to deploy a contract whose ctor takes type `t`."""
    if t in _CTOR_DEFAULT_PER_TYPE:
        return _CTOR_DEFAULT_PER_TYPE[t]
    if t.startswith("uint") or t.startswith("int"):
        return "uint256(1)" if t.startswith("uint") else "int256(1)"
    if re.match(r"^bytes\d+$", t):
        # fixed-size bytes — use zero-padded literal
        n = int(t[5:])
        return f"bytes{n}(0)"
    if t.endswith("[]"):  # empty dynamic array
        inner = _expand_abi_type(t[:-2], components)
        return f"new {inner}[](0)"
    if t.startswith("tuple") and components:
        # build a tuple literal of defaults
        inner = ", ".join(
            _solidity_default_for(c.get("type", ""), c.get("components"))
            for c in components
        )
        return f"({inner})"
    # Fallback — let solc figure it out (zero-value for value types)
    return f"{t}(0)"


def _constructor_encode_call(abi: list[dict]) -> str:
    """Return Solidity code that ABI-encodes constructor args, or '' if none.

    Output is meant to be substituted into:
        bytes memory _bc = vm.getCode(...);
        ${ctor_args_concat}     // injected here
        // _bc now has args appended (or unchanged if no ctor args)
    """
    ctor = _find_constructor_abi(abi)
    if not ctor:
        return ""
    inputs = ctor.get("inputs", [])
    if not inputs:
        return ""
    defaults = ", ".join(
        _solidity_default_for(i.get("type", ""), i.get("components"))
        for i in inputs
    )
    return (
        f"bytes memory _ctorArgs = abi.encode({defaults});\n"
        f"        _bc = bytes.concat(_bc, _ctorArgs);"
    )


# ── Pragma detection ──────────────────────────────────────────────────────────

# Tolerant of `^`, `~`, `>=`, `<=`, etc. — we grab the first major.minor we see.
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+[^\d]*(\d+)\.(\d+)")


def _pragma_major_minor(source: str) -> tuple[int, int] | None:
    """Parse `pragma solidity ^X.Y...;` from a source string."""
    if not source:
        return None
    m = _PRAGMA_RE.search(source)
    return (int(m.group(1)), int(m.group(2))) if m else None


def _detect_mode(source: str | None) -> str:
    """Pick 'legacy' or 'modern' from the contract's pragma.

    'modern'  — solc ≥ 0.8 → current behavior (import source, `new ContractName()`)
    'legacy'  — solc < 0.8 → interface + `vm.getCode` + assembly `create`
    """
    if not source:
        return "modern"
    v = _pragma_major_minor(source)
    if v is None:
        return "modern"
    return "legacy" if v < (0, 8) else "modern"


# Boundary values used when synthesizing a random arg for the reentrancy fallback.
# Mirrors the spirit of fuzzer/mutator.py::_UINT_BOUNDARIES — kept inline to avoid
# a cross-module dependency between two siblings under fuzzer/.
_REENTRY_UINT_BOUNDARIES = (0, 1, 2, 2**8 - 1, 2**64 - 1, 2**256 - 1)


def _random_arg_for_type(sol_type: str) -> str | int | bool:
    """Synthesize a plausible random value for a Solidity arg type.

    Used by FoundryFuzzer._reentry_setup_lines when the LLM under-specifies (or
    hallucinates) the reentry function and we need to fill the arg slots from
    scratch.  The output is passed through `_normalize_arg(arg, sol_type)` like
    any other argument — same coercion path as LLM-supplied values.
    """
    if sol_type == "address":
        return "attacker_address"
    if sol_type == "bool":
        return random.choice([True, False])
    if "int" in sol_type:
        return hex(random.choice(_REENTRY_UINT_BOUNDARIES))
    if "bytes" in sol_type:
        return "0x"
    return "0x0"
