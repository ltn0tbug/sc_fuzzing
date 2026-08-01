"""Coverage measurement from `forge test --debug --dump` traces.

Replaces `forge coverage` entirely. Works for any solc version (0.4 → 0.8+)
because we read traces from the EVM execution instead of running solar over the
source.

Flow per iteration:
  1. forge test --match-path … --debug --dump <file> --allow-failure   (single invocation)
  2. parse_dump(file, target_contract_name) → DumpData
  3. compute_coverage_from_dump(DumpData, BytecodeMeta) → IterationCoverage
  4. (optional) to_lcov(IterationCoverage, BytecodeMeta) → lcov.info text

`BytecodeMeta` is loaded once at startup from the artifact JSON
(`out/<file>.sol/<contract>.json`) — gives us the source map, pc→IC map,
deployed bytecode, and the source text. Source map + bytecode are stable across
solc versions (the source-map format itself hasn't changed in years).

Four coverage granularities are produced per iteration:
  - branches:    source-level — unique (source_line, direction) pairs after
                 source-line dedup and dispatcher filter. Matches what
                 `forge coverage --lcov` produces. Logged for human reading.
  - bc_branches: bytecode-level — unique (JUMPI_pc, direction) pairs, raw,
                 no dedup, no dispatcher filter. **Drives the reward signal.**
                 Strictly ≥ source-level branches (every source-line dedup
                 collapse becomes 1+ separate bc-branches).
  - lines:       unique source line numbers hit (from the source map). Useful
                 for human interpretation in the run log.
  - functions:   unique function names where any body line was hit.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# ── EVM opcode constants ──────────────────────────────────────────────────────
_OP_JUMPI = 0x57
_OP_PUSH1 = 0x60
_OP_PUSH32 = 0x7F


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class BytecodeMeta:
    """Pre-computed metadata for one contract — loaded once at fuzzer startup."""
    contract_name: str
    source_path: str               # path printed into lcov SF: records
    source_text: str               # raw Solidity source
    file_id: int                   # source-map `index` value matching this file
    source_map: list[dict]         # runtime source-map entries (one per IC)
    pc_ic_map: dict[int, int]      # PC → instruction count
    runtime_bytecode: bytes        # deployed bytecode
    all_pcs: frozenset[int]        # every reachable PC in runtime bytecode
    all_jumpi_pcs: frozenset[int]  # subset of all_pcs that are JUMPI opcodes
    executable_lines: frozenset[int]  # source lines that any runtime PC maps to
    fn_decls: list[tuple[int, str]]   # [(line_no, fn_name), ...] in declaration order
    fn_line_ranges: dict[str, tuple[int, int]]  # fn → (start_line, end_line_exclusive)
    # Source-level branch positions. Multiple JUMPI opcodes can map to the same
    # source location (e.g., compiler-generated overflow checks for one source
    # expression). We dedupe by source line so our branch count matches what
    # `forge coverage --lcov` produces (source-level, not instruction-level).
    # Maps source line → set of JUMPI PCs at that line.
    source_branches: dict[int, frozenset[int]] = field(default_factory=dict)
    # Reverse index: JUMPI PC → source line. Used to fold instruction-level
    # branch hits up to the source level.
    jumpi_pc_to_line: dict[int, int] = field(default_factory=dict)
    # Raw solc AST (`SourceUnit` root). Present when `forge build --ast` was
    # used (default for our runner). Walked at load time to derive ground-truth
    # branch positions; also exposed to `ContractFeatures.from_ast`.
    ast: dict | None = None

    # ── On-chain-anchored tier (fork mode; None for inline) ───────────────────
    # For a fork target the ARTIFACT may not reproduce the deployed bytecode
    # (solc/optimizer/evm drift), which invalidates the artifact-derived JUMPI
    # denominator + source map. When the on-chain runtime bytecode is available
    # we anchor the ALWAYS-correct metrics (bc-branch total, function coverage) on
    # it — numerator (arena PCs) and denominator (on-chain JUMPIs) then share one
    # PC space. `coverage_unreliable` flags that the SOURCE tier (line/src-branch)
    # can't be trusted for this target (artifact opcode-stream ≠ on-chain), so
    # those numbers are suppressed rather than reported as bogus small values.
    onchain_all_jumpi_pcs: frozenset[int] | None = None   # bc denominator when set
    onchain_all_pcs: frozenset[int] | None = None
    # fn name → the dispatcher body-entry PCs for its selector(s) in ON-CHAIN PC
    # space (overloads collapse by name). A function is "hit" iff any of its entry
    # PCs was executed. ABI-named via the artifact's `methodIdentifiers`.
    onchain_fn_entries: dict[str, frozenset[int]] | None = None
    coverage_unreliable: bool = False    # source tier untrustworthy (fork drift / no anchor)
    onchain_lcp: float = 1.0             # opcode-stream LCP(artifact, on-chain); 1.0 = inline/identical

    @property
    def total_branches(self) -> int:
        # Source-level: 2 directions per source-line that has a JUMPI.
        # (forge coverage --lcov uses this same convention.)
        return 2 * len(self.source_branches)

    @property
    def total_bc_branches(self) -> int:
        # Bytecode-level: 2 directions per JUMPI opcode. Anchored on the ON-CHAIN
        # runtime bytecode when available (fork) so the denominator shares the
        # arena's PC space — ALWAYS correct even when the artifact drifted. Falls
        # back to the artifact's JUMPIs for inline (freshly-deployed own code).
        # Drives the reward signal (see fuzzer/reward.py).
        jset = self.onchain_all_jumpi_pcs if self.onchain_all_jumpi_pcs is not None else self.all_jumpi_pcs
        return 2 * len(jset)

    @property
    def total_lines(self) -> int:
        return len(self.executable_lines)

    @property
    def total_functions(self) -> int:
        # On-chain dispatcher functions when anchored (fork), else source decls.
        if self.onchain_fn_entries is not None:
            return len(self.onchain_fn_entries)
        return len(self.fn_decls)


@dataclass
class IterationCoverage:
    """Coverage measured for a single fuzz iteration."""
    # Source-level branch IDs hit this iter — each is (source_line, direction).
    # Multiple JUMPI opcodes at the same source line collapse to one entry.
    branches_hit: frozenset[tuple[int, int]] = field(default_factory=frozenset)
    # Per-(source_line, direction) hit counts (for lcov emission)
    branch_hit_counts: dict[tuple[int, int], int] = field(default_factory=dict)
    # Bytecode-level branch IDs hit this iter — each is (jumpi_pc, direction).
    # No source-line dedup, no dispatcher filter — drives the reward signal.
    bc_branches_hit: frozenset[tuple[int, int]] = field(default_factory=frozenset)
    # Per-(jumpi_pc, direction) hit counts
    bc_branch_hit_counts: dict[tuple[int, int], int] = field(default_factory=dict)
    # Source line numbers hit this iter
    lines_hit: frozenset[int] = field(default_factory=frozenset)
    # Per-line hit counts (sum across all steps)
    line_hit_counts: dict[int, int] = field(default_factory=dict)
    # Function names hit this iter
    functions_hit: frozenset[str] = field(default_factory=frozenset)
    # Per-function call counts (best-effort)
    function_hit_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class DumpData:
    """Subset of the `forge test --debug --dump` payload we actually need."""
    target_addr: str | None        # checksummed address of the contract under test
    # All PCs executed at the target address, with hit counts
    pc_hits: dict[int, int]
    # JUMPI step sequences — list of (jumpi_pc, next_step_pc) tuples; next_pc tells us direction
    jumpi_sequences: list[tuple[int, int]]


# ── Loading BytecodeMeta from an artifact ─────────────────────────────────────


_FN_DECL_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")

# Control-flow constructs that compile to JUMPIs in the bytecode. Used to
# filter out JUMPIs at compiler-generated positions (dispatcher, getters,
# overflow checks) so our branch count matches forge coverage's convention.
# This regex is the legacy fallback path; AST walking (see `_ast_branch_ranges`)
# is the primary source-of-truth when `BytecodeMeta.ast` is populated.
_BRANCH_KEYWORD_RE = re.compile(
    r"\b(if|else if|while|for|require|assert)\s*\("
    r"|\?\s*[^:]*?:"        # ternary `cond ? a : b`
    r"|&&|\|\|"             # short-circuit operators
)

# AST node types that represent user-level branch decisions. Matches what solc
# emits a JUMPI for in runtime bytecode (plus the require/assert calls which
# compile to conditional reverts). Walking the AST for these gives exact byte
# ranges, eliminating the regex heuristic + dispatcher-range filter.
_AST_BRANCH_NODE_TYPES = frozenset({
    "IfStatement",          # if (cond) { … } else { … }
    "Conditional",          # cond ? a : b
    "WhileStatement",       # while (cond) { … }
    "DoWhileStatement",     # do { … } while (cond);
    "ForStatement",         # for (init; cond; step) { … }
})

_AST_SHORT_CIRCUIT_OPS = frozenset({"&&", "||"})


def _ast_branch_ranges(ast: dict | None) -> list[tuple[int, int]]:
    """Walk the solc AST, return [(src_offset, src_length), …] for every
    user-level branch decision.

    Covers `if`, `?:`, `while`, `do-while`, `for`, `&&`, `||`, and calls to
    `require`/`assert` (which compile to a JUMPI). Compiler-generated JUMPIs
    (dispatcher selectors, modifier guards, 0.8 overflow checks) don't appear
    in the AST, so they're naturally excluded — no >50%-range heuristic needed.
    """
    if not ast:
        return []
    out: list[tuple[int, int]] = []
    stack: list[dict] = [ast]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        nt = node.get("nodeType")
        if nt in _AST_BRANCH_NODE_TYPES:
            src = node.get("src", "")
            try:
                off, ln, _fid = src.split(":")
                out.append((int(off), int(ln)))
            except (ValueError, AttributeError):
                pass
        elif nt == "BinaryOperation" and node.get("operator") in _AST_SHORT_CIRCUIT_OPS:
            src = node.get("src", "")
            try:
                off, ln, _fid = src.split(":")
                out.append((int(off), int(ln)))
            except (ValueError, AttributeError):
                pass
        elif nt == "FunctionCall":
            # require(…) / assert(…) compile to a conditional revert (JUMPI).
            expr = node.get("expression") or {}
            if expr.get("nodeType") == "Identifier" and expr.get("name") in ("require", "assert"):
                src = node.get("src", "")
                try:
                    off, ln, _fid = src.split(":")
                    out.append((int(off), int(ln)))
                except (ValueError, AttributeError):
                    pass
        # Recurse into all dict children + lists thereof
        for v in node.values():
            if isinstance(v, dict):
                stack.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        stack.append(item)
    return out


def _find_branch_keyword_positions(source_text: str) -> list[tuple[int, int]]:
    """Return [(start_offset, end_offset), ...] for every control-flow keyword.

    These are the source ranges that compile to user-level branch decisions.
    A JUMPI's source-map range must overlap one of these for us to count it
    as a source-level branch (filters out compiler-generated JUMPIs like
    dispatcher selectors, public getters, and 0.8 overflow checks).
    """
    return [(m.start(), m.end()) for m in _BRANCH_KEYWORD_RE.finditer(source_text)]


def _first_keyword_in_range(
    keyword_positions: list[tuple[int, int]],
    range_start: int,
    range_end: int,
    line_starts: list[int],
) -> int | None:
    """Return the line number of the first branch keyword whose start lies in
    [range_start, range_end), or None if no keyword falls in that range.

    Using `bisect` keeps this O(log N) per JUMPI even for large contracts.
    """
    from bisect import bisect_left, bisect_right
    starts = [s for s, _ in keyword_positions]
    lo = bisect_left(starts, range_start)
    hi = bisect_right(starts, range_end)
    if lo >= hi:
        return None
    # First keyword whose start falls inside the JUMPI's source range
    kw_start = keyword_positions[lo][0]
    return _line_for_offset(line_starts, kw_start)


def _offset_to_line_index(source_text: str) -> list[int]:
    """Return a sorted list of byte offsets at which each line starts (line 1 starts at 0)."""
    starts = [0]
    for i, ch in enumerate(source_text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _line_for_offset(line_starts: list[int], offset: int) -> int:
    """Binary search: which 1-based line contains the given byte offset?"""
    from bisect import bisect_right
    return bisect_right(line_starts, offset)


def _parse_solc_source_map(s: str) -> list[dict]:
    """Decode solc's compact source-map string into a list of {offset, length, index, jump, modifier_depth}.

    Format: `s:l:f:j:m;s:l:f:j:m;...` — empty fields inherit from the previous entry.
    """
    out: list[dict] = []
    prev = {"offset": 0, "length": 0, "index": 0, "jump": "-", "modifier_depth": 0}
    for entry in s.split(";"):
        parts = entry.split(":")
        cur = dict(prev)
        if len(parts) > 0 and parts[0] != "":
            cur["offset"] = int(parts[0])
        if len(parts) > 1 and parts[1] != "":
            cur["length"] = int(parts[1])
        if len(parts) > 2 and parts[2] != "":
            cur["index"] = int(parts[2])
        if len(parts) > 3 and parts[3] != "":
            cur["jump"] = parts[3]
        if len(parts) > 4 and parts[4] != "":
            cur["modifier_depth"] = int(parts[4])
        out.append(cur)
        prev = cur
    return out


def _disassemble_pcs(runtime_bytecode: bytes) -> tuple[frozenset[int], frozenset[int]]:
    """Walk the runtime bytecode and return (all_pcs, jumpi_pcs)."""
    all_pcs: set[int] = set()
    jumpi_pcs: set[int] = set()
    pc = 0
    n = len(runtime_bytecode)
    while pc < n:
        all_pcs.add(pc)
        op = runtime_bytecode[pc]
        if op == _OP_JUMPI:
            jumpi_pcs.add(pc)
        if _OP_PUSH1 <= op <= _OP_PUSH32:
            pc += 1 + (op - _OP_PUSH1 + 1)
        else:
            pc += 1
    return frozenset(all_pcs), frozenset(jumpi_pcs)


def _build_pc_ic_map(runtime_bytecode: bytes) -> dict[int, int]:
    """Compute pc → instruction-count map for the runtime bytecode.

    solc's source map is indexed by instruction count (= ordinal position of
    each opcode, treating each multi-byte PUSH as one instruction).
    """
    pc_ic: dict[int, int] = {}
    pc = 0
    ic = 0
    n = len(runtime_bytecode)
    while pc < n:
        pc_ic[pc] = ic
        op = runtime_bytecode[pc]
        if _OP_PUSH1 <= op <= _OP_PUSH32:
            pc += 1 + (op - _OP_PUSH1 + 1)
        else:
            pc += 1
        ic += 1
    return pc_ic


# Modern solc (>=0.5) link placeholder: "__$" + 34 hex + "$__" — exactly 40 hex
# chars, i.e. the 20-byte library-address slot.
_LINK_PLACEHOLDER_RE = re.compile(r"__\$[0-9a-fA-F]{34}\$__")


def _zero_link_placeholders(hex_body: str, link_refs: dict | None) -> str:
    """Replace unlinked library placeholders in a bytecode hex string with a zero
    address, preserving byte alignment (each is a 20-byte PUSH immediate).

    Authoritative path uses the artifact's `linkReferences` byte offsets/lengths;
    a regex over the modern `__$<hash>$__` form is applied afterward to catch any
    placeholder not covered by linkReferences. Returns the (possibly still
    placeholder-bearing) hex; the caller re-checks and disables coverage if any
    remain unresolved.
    """
    if link_refs:
        chars = list(hex_body)
        for file_refs in link_refs.values():
            if not isinstance(file_refs, dict):
                continue
            for spots in file_refs.values():
                for spot in spots or ():
                    start = int(spot.get("start", -1)) * 2
                    length = int(spot.get("length", 0)) * 2
                    if start < 0:
                        continue
                    for i in range(start, min(start + length, len(chars))):
                        chars[i] = "0"
        hex_body = "".join(chars)
    return _LINK_PLACEHOLDER_RE.sub("0" * 40, hex_body)


# ── On-chain bytecode anchor (fork-coverage fidelity) ─────────────────────────
# Solidity source maps key on instruction count, so the artifact's source map is
# valid for the on-chain PCs iff the two opcode STREAMS match (PUSH immediates +
# trailing CBOR metadata are irrelevant to IC alignment). We compare opcode-only
# streams; a low longest-common-prefix fraction ⇒ the recompile drifted from the
# deployed bytecode and the source tier can't be trusted. The threshold is
# generous (0.98) because harmless tail differences — metadata length, immutable
# fills — shorten the LCP slightly on an otherwise-faithful recompile.
_RELIABLE_LCP_THRESHOLD = 0.98

_OP_PUSH4 = 0x63


def opcode_stream(code: bytes) -> list[int]:
    """Opcode-only sequence (each multi-byte PUSH counts once; its immediate is
    skipped). Trailing metadata is consumed naturally by the PUSH walk."""
    ops: list[int] = []
    pc, n = 0, len(code)
    while pc < n:
        op = code[pc]
        ops.append(op)
        if _OP_PUSH1 <= op <= _OP_PUSH32:
            pc += op - _OP_PUSH1 + 1
        pc += 1
    return ops


def opcode_lcp(a: bytes, b: bytes) -> float:
    """Longest-common-prefix fraction of two bytecodes' opcode streams (1.0 =
    identical prefix over the longer stream; 0.0 = diverge at instruction 0)."""
    sa, sb = opcode_stream(a), opcode_stream(b)
    m = min(len(sa), len(sb))
    i = 0
    while i < m and sa[i] == sb[i]:
        i += 1
    longer = max(len(sa), len(sb))
    return i / longer if longer else 1.0


def parse_dispatcher(code: bytes, valid_selectors: frozenset[str]) -> dict[str, int]:
    """Parse the runtime dispatcher → {selector_hex: body-entry PC}.

    Recognises the version-independent shape `PUSH4 <selector> … PUSHk <dest> …
    JUMPI` (solc 0.4 → 0.8 all emit a selector compare that pushes the function's
    JUMPDEST and conditionally jumps to it). Only selectors present in
    `valid_selectors` (the ABI's `methodIdentifiers`) are kept, so stray PUSH4
    constants (the Panic selector, magic numbers) can't masquerade as functions.
    `selector_hex` is lowercase, no `0x`.
    """
    # Tokenize into (op, immediate_int_or_None).
    toks: list[tuple[int, int | None]] = []
    pc, n = 0, len(code)
    while pc < n:
        op = code[pc]
        if _OP_PUSH1 <= op <= _OP_PUSH32:
            k = op - _OP_PUSH1 + 1
            imm = int.from_bytes(code[pc + 1:pc + 1 + k], "big")
            toks.append((op, imm))
            pc += 1 + k
        else:
            toks.append((op, None))
            pc += 1
    out: dict[str, int] = {}
    for i, (op, imm) in enumerate(toks):
        if op != _OP_PUSH4 or imm is None:
            continue
        sel = f"{imm:08x}"
        if sel not in valid_selectors:
            continue
        # Look ahead a small window for the pushed JUMPDEST then the JUMPI.
        dest = None
        for j in range(i + 1, min(i + 7, len(toks))):
            oj, ij = toks[j]
            if _OP_PUSH1 <= oj <= _OP_PUSH32 and ij is not None:
                dest = ij
            elif oj == _OP_JUMPI:
                if dest is not None:
                    out[sel] = dest
                break
    return out


def _build_onchain_fn_entries(
    onchain_code: bytes, method_identifiers: dict | None
) -> dict[str, frozenset[int]]:
    """fn name → dispatcher body-entry PCs (on-chain), from the on-chain
    dispatcher ∩ the artifact's `methodIdentifiers` (name↔selector, which is
    keccak-derived and thus solc-version-independent — reliable even when the
    bytecode drifted). Overloads collapse by name."""
    if not method_identifiers:
        return {}
    sel_to_name = {
        (sel[2:] if str(sel).startswith("0x") else str(sel)).lower(): sig.split("(", 1)[0]
        for sig, sel in method_identifiers.items()
    }
    dispatch = parse_dispatcher(onchain_code, frozenset(sel_to_name))
    entries: dict[str, set[int]] = {}
    for sel, dest in dispatch.items():
        entries.setdefault(sel_to_name[sel], set()).add(dest)
    return {name: frozenset(pcs) for name, pcs in entries.items()}


# ── On-chain runtime bytecode fetch (fork mode; NOT called in unit tests) ──────
# EIP-1967 implementation slot: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
_EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_RPC_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def _rpc_call(url: str, method: str, params: list, *, timeout: float = 10.0):
    """Single JSON-RPC POST (browser UA — public edges 403 the urllib default).
    Returns the `result` field or None on any failure."""
    import json as _json
    import urllib.request
    payload = _json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params}).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": _RPC_UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = _json.loads(resp.read())
    except Exception:
        return None
    return data.get("result") if isinstance(data, dict) else None


def resolve_eip1967_impl(rpc_endpoints: list[str], proxy_addr: str, block: int) -> str | None:
    """Read the EIP-1967 implementation-slot storage at `block` → impl address, or
    None if the slot is empty / unreachable. Tries each endpoint in order."""
    for url in rpc_endpoints:
        raw = _rpc_call(url, "eth_getStorageAt", [proxy_addr, _EIP1967_IMPL_SLOT, hex(block)])
        if not raw or not isinstance(raw, str):
            continue
        word = raw[2:] if raw.startswith("0x") else raw
        if len(word) < 40 or int(word, 16) == 0:
            continue
        return "0x" + word[-40:]
    return None


def fetch_onchain_code(rpc_endpoints: list[str], address: str, block: int) -> bytes | None:
    """`eth_getCode(address, block)` over the ordered endpoints → runtime bytes,
    or None if every endpoint fails / the account has no code. Live network — the
    caller (foundry.compile) is fork-only and pre-flighted; unit tests inject
    bytes instead of calling this."""
    for url in rpc_endpoints:
        raw = _rpc_call(url, "eth_getCode", [address, hex(block)])
        if not raw or not isinstance(raw, str):
            continue
        body = raw[2:] if raw.startswith("0x") else raw
        if not body or body in ("0", "00"):
            continue
        try:
            return bytes.fromhex(body)
        except ValueError:
            continue
    return None


def load_bytecode_meta(
    foundry_project: Path,
    contract_name: str,
    source_text: str | None = None,
    source_filename: str | None = None,
    onchain_bytecode: bytes | None = None,
    out_dir: Path | None = None,
) -> BytecodeMeta | None:
    """Load BytecodeMeta from the standard Foundry artifact location.

    Returns None if the artifact cannot be located or is missing the fields we
    need — callers should handle gracefully (coverage disabled for that contract).

    `onchain_bytecode` (fork mode): the runtime code that actually executes on the
    fork (the impl's code for a proxy). When given, the ALWAYS-correct tier
    (bc-branch denominator, function coverage) is anchored on it, and the SOURCE
    tier is flagged `coverage_unreliable` when the artifact's opcode stream drifts
    from on-chain (opcode-LCP < threshold) so bogus source numbers are suppressed.
    None (inline) → artifact-anchored throughout, always reliable.

    `out_dir` overrides the artifact search root (default `foundry_project/out`).
    Fork mode uses it to read a target-only coverage build compiled under the
    target's real EVM (see `FoundryFuzzer.compile`), which the shared `out/` can't
    hold when that EVM is incompatible with forge-std's (pre-Constantinople targets).
    """
    out_dir = out_dir if out_dir is not None else foundry_project / "out"
    if not out_dir.is_dir():
        logger.warning("No out/ directory at %s — coverage disabled", out_dir)
        return None

    # Look for the artifact file. Conventional layout: out/<file>.sol/<contract>.json.
    candidates: list[Path] = []
    if source_filename:
        candidates.append(out_dir / f"{source_filename}.sol" / f"{contract_name}.json")
    candidates.append(out_dir / f"{contract_name}.sol" / f"{contract_name}.json")
    # Fall back to a directory scan
    for p in out_dir.glob(f"*.sol/{contract_name}.json"):
        candidates.append(p)

    artifact_path = next((p for p in candidates if p.is_file()), None)
    if artifact_path is None:
        logger.warning("No artifact for contract %s under %s — coverage disabled", contract_name, out_dir)
        return None

    try:
        artifact = json.loads(artifact_path.read_text())
    except Exception as e:
        logger.warning("Could not parse artifact %s (%s) — coverage disabled", artifact_path, e)
        return None

    deployed = artifact.get("deployedBytecode") or {}
    if isinstance(deployed, str):
        bytecode_hex = deployed
        source_map_str = ""
    else:
        bytecode_hex = deployed.get("object", "")
        source_map_str = deployed.get("sourceMap", "")

    if not bytecode_hex or bytecode_hex in ("0x", "0x0"):
        logger.warning("Artifact %s has empty deployedBytecode — coverage disabled", artifact_path)
        return None
    if not source_map_str:
        logger.warning("Artifact %s has no deployedBytecode.sourceMap — coverage disabled", artifact_path)
        return None

    hex_body = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
    # Unlinked-library placeholders ("__$keccakHash$__") leak into deployedBytecode
    # when the contract uses external libraries that aren't linked at compile time
    # — common for full DeFi protocols. They aren't real hex and crash
    # bytes.fromhex(). Each placeholder occupies exactly the 20-byte slot of the
    # library address (a PUSH20 immediate), so substituting a zero address keeps
    # every downstream PC offset identical to the on-chain linked bytecode — the
    # JUMPI enumeration (denominator) and the dump's on-chain PCs (numerator) stay
    # aligned. We therefore zero-link rather than discard the whole contract.
    if "__" in hex_body or "$" in hex_body:
        link_refs = deployed.get("linkReferences") if isinstance(deployed, dict) else None
        hex_body = _zero_link_placeholders(hex_body, link_refs)
        if "__" in hex_body or "$" in hex_body:
            # A placeholder we couldn't locate/zero out — fall back to disabling
            # coverage (fuzzing still works via the ABI interface).
            logger.warning(
                "Artifact %s has unresolvable library placeholders — coverage disabled",
                artifact_path,
            )
            return None
        logger.info("Zero-linked library placeholder(s) in %s for coverage.", artifact_path)
    runtime_bytecode = bytes.fromhex(hex_body)
    source_map = _parse_solc_source_map(source_map_str)
    pc_ic_map = _build_pc_ic_map(runtime_bytecode)
    all_pcs, all_jumpi_pcs = _disassemble_pcs(runtime_bytecode)

    # Determine source text + file_id
    if source_text is None:
        # The artifact embeds metadata.sources; try to pick it up
        meta_sources = (artifact.get("metadata", {}) or {}).get("sources", {})
        for src_path, src_info in meta_sources.items():
            content = (src_info or {}).get("content")
            if content and contract_name in content:
                source_text = content
                source_path_for_lcov = src_path
                break
        else:
            logger.warning("No source text found for %s — coverage disabled", contract_name)
            return None
    else:
        # Use the conventional src/<contract>.sol path for lcov SF: records
        source_path_for_lcov = (
            f"src/{source_filename}.sol" if source_filename else f"src/{contract_name}.sol"
        )

    # file_id: find which solc source index corresponds to our file.
    # forge artifacts include `ast.absolutePath`; we match by checking the source map's first non-(-1) index.
    file_id = 0
    for e in source_map:
        if e["index"] != -1:
            file_id = e["index"]
            break

    # Pre-compute line lookup
    line_starts = _offset_to_line_index(source_text)
    def _line(off: int) -> int:
        return _line_for_offset(line_starts, off)

    # Executable lines: every line that any runtime IC maps into
    executable_lines: set[int] = set()
    for pc, ic in pc_ic_map.items():
        if ic >= len(source_map):
            continue
        e = source_map[ic]
        if e["index"] != file_id or e["offset"] < 0:
            continue
        executable_lines.add(_line(e["offset"]))

    # Source-level branches.
    #
    # Primary path (AST present): a JUMPI is a "real" user-level branch iff its
    # source-map offset falls inside an AST branch-node's source range
    # (IfStatement, Conditional, While/DoWhile/For, &&/||, require/assert).
    # The AST naturally excludes dispatcher/getter/overflow JUMPIs since solc
    # doesn't emit those as user-level nodes — no >50%-range heuristic needed.
    #
    # Fallback (no AST): the legacy regex + half-source-range filter.
    ast = artifact.get("ast") if isinstance(artifact, dict) else None
    branch_ranges = _ast_branch_ranges(ast)
    source_branches_tmp: dict[int, set[int]] = {}
    jumpi_pc_to_line: dict[int, int] = {}
    if branch_ranges:
        # Linear containment check — typical contracts have <100 branch ranges,
        # so O(jumpi × ranges) is well under a millisecond.
        def _jumpi_is_user_branch(off: int) -> bool:
            return any(r_off <= off < r_off + r_len for r_off, r_len in branch_ranges)
        for jpc in all_jumpi_pcs:
            ic = pc_ic_map.get(jpc)
            if ic is None or ic >= len(source_map):
                continue
            e = source_map[ic]
            if e["index"] != file_id or e["offset"] < 0:
                continue
            if not _jumpi_is_user_branch(e["offset"]):
                continue  # compiler-generated JUMPI — not in any AST branch node
            line = _line(e["offset"])
            source_branches_tmp.setdefault(line, set()).add(jpc)
            jumpi_pc_to_line[jpc] = line
    else:
        # Legacy fallback: regex-free range filter (drop dispatcher JUMPIs by width).
        half_source_len = len(source_text) // 2
        for jpc in all_jumpi_pcs:
            ic = pc_ic_map.get(jpc)
            if ic is None or ic >= len(source_map):
                continue
            e = source_map[ic]
            if e["index"] != file_id or e["offset"] < 0:
                continue
            if e["length"] > half_source_len:
                continue
            line = _line(e["offset"])
            source_branches_tmp.setdefault(line, set()).add(jpc)
            jumpi_pc_to_line[jpc] = line
    source_branches: dict[int, frozenset[int]] = {
        ln: frozenset(pcs) for ln, pcs in source_branches_tmp.items()
    }

    # Function declarations (by name + start line). Used for FN/FNDA records.
    fn_decls: list[tuple[int, str]] = []
    for m in _FN_DECL_RE.finditer(source_text):
        line = source_text[: m.start()].count("\n") + 1
        fn_decls.append((line, m.group(1)))
    fn_line_ranges: dict[str, tuple[int, int]] = {}
    for i, (line, name) in enumerate(fn_decls):
        end = fn_decls[i + 1][0] if i + 1 < len(fn_decls) else (source_text.count("\n") + 2)
        fn_line_ranges[name] = (line, end)

    # ── On-chain-anchored tier (fork). Anchor bc-branch + function coverage on
    # the deployed code so they're correct regardless of artifact drift; flag the
    # SOURCE tier unreliable when the opcode streams diverge. ──────────────────
    onchain_all_jumpi_pcs = None
    onchain_all_pcs = None
    onchain_fn_entries = None
    coverage_unreliable = False
    onchain_lcp = 1.0
    if onchain_bytecode:
        onchain_all_pcs, onchain_all_jumpi_pcs = _disassemble_pcs(onchain_bytecode)
        onchain_fn_entries = _build_onchain_fn_entries(
            onchain_bytecode, artifact.get("methodIdentifiers") if isinstance(artifact, dict) else None
        )
        onchain_lcp = opcode_lcp(runtime_bytecode, onchain_bytecode)
        coverage_unreliable = onchain_lcp < _RELIABLE_LCP_THRESHOLD
        if coverage_unreliable:
            logger.warning(
                "Coverage: %s artifact opcode-stream diverges from on-chain "
                "(LCP=%.3f < %.2f) — SOURCE line/branch coverage suppressed as "
                "unreliable; bc-branch + function coverage anchored on-chain "
                "(%d JUMPIs, %d functions). Likely cause: solc/optimizer/evm "
                "settings the recompile couldn't reproduce.",
                contract_name, onchain_lcp, _RELIABLE_LCP_THRESHOLD,
                len(onchain_all_jumpi_pcs), len(onchain_fn_entries),
            )

    return BytecodeMeta(
        contract_name=contract_name,
        source_path=source_path_for_lcov,
        source_text=source_text,
        file_id=file_id,
        source_map=source_map,
        pc_ic_map=pc_ic_map,
        runtime_bytecode=runtime_bytecode,
        all_pcs=all_pcs,
        all_jumpi_pcs=all_jumpi_pcs,
        executable_lines=frozenset(executable_lines),
        fn_decls=fn_decls,
        fn_line_ranges=fn_line_ranges,
        source_branches=source_branches,
        jumpi_pc_to_line=jumpi_pc_to_line,
        ast=ast,
        onchain_all_jumpi_pcs=onchain_all_jumpi_pcs,
        onchain_all_pcs=onchain_all_pcs,
        onchain_fn_entries=onchain_fn_entries,
        coverage_unreliable=coverage_unreliable,
        onchain_lcp=onchain_lcp,
    )


# ── Parsing the dump.json forge test produces ─────────────────────────────────


def parse_dump(
    dump_path: Path,
    target_contract_name: str,
    target_address_override: str | None = None,
) -> DumpData:
    """Extract per-target-contract PC hits + JUMPI directions from a forge dump.

    In normal (clean-room) mode, the contract is freshly deployed and forge's
    `identified_contracts` map names it; we look it up by name. In FORK mode
    the live target contract isn't deployed locally, so it never appears in
    `identified_contracts` — pass `target_address_override` (the on-chain
    address from ForkConfig) to bypass the name lookup. Addresses are compared
    lowercased.
    """
    data = json.loads(dump_path.read_text())

    if target_address_override:
        target_addr = target_address_override.lower()
        # Sanity: ensure the dump actually traced this address. If not, return
        # empty so the caller doesn't trust stale data.
        seen = {
            (arena.get("address") or "").lower()
            for arena in data.get("debug_arena", [])
        }
        if target_addr not in seen:
            return DumpData(target_addr=None, pc_hits={}, jumpi_sequences=[])
    else:
        identified = data.get("contracts", {}).get("identified_contracts", {})
        target_addr = next(
            (addr for addr, name in identified.items() if name == target_contract_name),
            None,
        )
        if target_addr is None:
            return DumpData(target_addr=None, pc_hits={}, jumpi_sequences=[])
        target_addr = target_addr.lower()

    pc_hits: dict[int, int] = {}
    jumpi_sequences: list[tuple[int, int]] = []

    for arena in data.get("debug_arena", []):
        if (arena.get("address") or "").lower() != target_addr:
            continue
        if arena.get("kind") not in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):
            continue
        steps = arena.get("steps") or []
        for i, step in enumerate(steps):
            pc = step["pc"]
            pc_hits[pc] = pc_hits.get(pc, 0) + 1
            if step["op"] == _OP_JUMPI and i + 1 < len(steps):
                jumpi_sequences.append((pc, steps[i + 1]["pc"]))

    return DumpData(target_addr=target_addr, pc_hits=pc_hits, jumpi_sequences=jumpi_sequences)


# ── Coverage computation ──────────────────────────────────────────────────────


def compute_coverage_from_dump(dump: DumpData, meta: BytecodeMeta) -> IterationCoverage:
    """Aggregate PC hits + JUMPI sequences into branch / line / function coverage."""
    cov = IterationCoverage()

    # `coverage_unreliable` ⇒ the artifact source map doesn't match the on-chain
    # PCs (fork drift), so the SOURCE tier (lines + source-level branches) would
    # be bogus. Suppress it (leave empty) rather than emit misleading numbers; the
    # bc-branch + function tiers below stay correct (on-chain-anchored).
    source_tier_ok = not meta.coverage_unreliable

    # ── Lines (source tier — suppressed when unreliable) ─────────────────────
    line_hit_counts: dict[int, int] = {}
    if source_tier_ok:
        line_starts = _offset_to_line_index(meta.source_text)
        for pc, hits in dump.pc_hits.items():
            ic = meta.pc_ic_map.get(pc)
            if ic is None or ic >= len(meta.source_map):
                continue
            e = meta.source_map[ic]
            if e["index"] != meta.file_id or e["offset"] < 0:
                continue
            line = _line_for_offset(line_starts, e["offset"])
            line_hit_counts[line] = line_hit_counts.get(line, 0) + hits
    cov.line_hit_counts = line_hit_counts
    cov.lines_hit = frozenset(line_hit_counts.keys())

    # ── Branches (source-level, matches forge coverage convention) ───────────
    # Fold instruction-level JUMPI hits up to their source line. Many JUMPIs
    # (compiler-generated overflow checks, modifier guards, dispatcher) map to
    # the same source position; we count each source decision once.
    # Branch key: (source_line, direction) where direction 0=taken, 1=not-taken.
    # ── Branches — both granularities walk the same JUMPI sequence ───────────
    branch_hit_counts: dict[tuple[int, int], int] = {}
    bc_branch_hit_counts: dict[tuple[int, int], int] = {}
    for jpc, next_pc in dump.jumpi_sequences:
        direction = 1 if next_pc == jpc + 1 else 0
        # Bytecode-level: every JUMPI counts; no source-line dedup, no filter.
        # These jpc are ON-CHAIN PCs (the arena executes the deployed code), so
        # they share the on-chain-anchored denominator's PC space — always valid.
        bc_key = (jpc, direction)
        bc_branch_hit_counts[bc_key] = bc_branch_hit_counts.get(bc_key, 0) + 1
        # Source-level: dedup by source line; skip JUMPIs the filter dropped.
        # Suppressed with the rest of the source tier when unreliable.
        if source_tier_ok:
            line = meta.jumpi_pc_to_line.get(jpc)
            if line is not None:
                key = (line, direction)
                branch_hit_counts[key] = branch_hit_counts.get(key, 0) + 1
    cov.branch_hit_counts = branch_hit_counts
    cov.branches_hit = frozenset(branch_hit_counts.keys())
    cov.bc_branch_hit_counts = bc_branch_hit_counts
    cov.bc_branches_hit = frozenset(bc_branch_hit_counts.keys())

    # ── Functions ────────────────────────────────────────────────────────────
    fn_counts: dict[str, int] = {}
    if meta.onchain_fn_entries is not None:
        # On-chain-anchored (fork): a function is hit iff any of its dispatcher
        # body-entry PCs was executed. ABI-named, always correct — independent of
        # the (possibly drifted) source map.
        for name, entry_pcs in meta.onchain_fn_entries.items():
            c = sum(dump.pc_hits.get(pc, 0) for pc in entry_pcs)
            if c > 0:
                fn_counts[name] = c
    else:
        # Inline: source-line-range method over our freshly-deployed own code.
        for name, (start, end) in meta.fn_line_ranges.items():
            c = sum(h for ln, h in line_hit_counts.items() if start <= ln < end)
            if c > 0:
                fn_counts[name] = c
    cov.function_hit_counts = fn_counts
    cov.functions_hit = frozenset(fn_counts.keys())

    return cov


# ── LCOV serialization (optional output for future use) ───────────────────────


def to_lcov(cov: IterationCoverage, meta: BytecodeMeta) -> str:
    """Serialize coverage data to standard LCOV format.

    Not used by the fuzzing loop today; provided for external tools (genhtml,
    lcov-merger, etc.) that may consume per-iteration or aggregated coverage.
    """
    lines: list[str] = []
    lines.append("TN:")
    lines.append(f"SF:{meta.source_path}")

    # Functions — fn_decls is [(line, name), ...]
    for line, name in meta.fn_decls:
        lines.append(f"FN:{line},{name}")
    for _, name in meta.fn_decls:
        hits = cov.function_hit_counts.get(name, 0)
        lines.append(f"FNDA:{hits},{name}")
    lines.append(f"FNF:{len(meta.fn_decls)}")
    lines.append(f"FNH:{sum(1 for _, n in meta.fn_decls if cov.function_hit_counts.get(n, 0) > 0)}")

    # Lines
    for ln in sorted(meta.executable_lines):
        hits = cov.line_hit_counts.get(ln, 0)
        lines.append(f"DA:{ln},{hits}")
    lines.append(f"LF:{len(meta.executable_lines)}")
    lines.append(f"LH:{sum(1 for ln in meta.executable_lines if cov.line_hit_counts.get(ln, 0) > 0)}")

    # Branches — one BRDA per (source_line, direction). Source-level grouping
    # matches what `forge coverage --lcov` emits: multiple JUMPIs at the same
    # source position count as one branch decision.
    for block_no, src_line in enumerate(sorted(meta.source_branches.keys())):
        for direction in (0, 1):
            hits = cov.branch_hit_counts.get((src_line, direction), 0)
            opposite_hit = cov.branch_hit_counts.get((src_line, 1 - direction), 0)
            hits_str = str(hits) if (hits > 0 or opposite_hit > 0) else "-"
            lines.append(f"BRDA:{src_line},{block_no},{direction},{hits_str}")
    total = 2 * len(meta.source_branches)
    hit = sum(1 for v in cov.branch_hit_counts.values() if v > 0)
    lines.append(f"BRF:{total}")
    lines.append(f"BRH:{hit}")
    lines.append("end_of_record")
    return "\n".join(lines) + "\n"
