"""Static feature extraction for EDA — Groups 1, 2, 3 from research.md §15.7.

Inputs: a Solidity source file (string) + optional ABI list (for external_fn_count).
Outputs: a flat dict of numeric / boolean features, one row per contract.

Heuristics are regex-based and conservative — over-counting is preferred to
under-counting because EDA uses rank-based statistics that are robust to
moderate measurement noise. Comments are stripped before pattern matching so
TODO/comment-only mentions don't inflate counts.
"""

from __future__ import annotations

import re
from typing import Any

# ── Preprocessing ─────────────────────────────────────────────────────────────

_BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLANK_LINE_RE = re.compile(r"\n\s*\n+")


def strip_comments(src: str) -> str:
    s = _BLOCK_COMMENT_RE.sub("", src)
    s = _LINE_COMMENT_RE.sub("", s)
    return s


def loc(src_no_comments: str) -> int:
    """Non-blank lines of code (Solidity LOC convention)."""
    return sum(1 for line in src_no_comments.splitlines() if line.strip())


# ── Group 1: Structure & complexity ───────────────────────────────────────────

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_IMPORT_RE = re.compile(r"^\s*import\s+[^;]+;", re.M)
_CONTRACT_RE = re.compile(r"^\s*(?:abstract\s+)?contract\s+(\w+)\s*(?:is\s+([^{]+))?", re.M)
_LIB_USE_RE = re.compile(r"^\s*using\s+(\w+)\s+for\s+", re.M)
_BRANCH_KWS_RE = re.compile(r"\b(if|for|while|require|assert)\s*\(")
_LOGIC_OP_RE = re.compile(r"(&&|\|\|)")


def cyclomatic_complexity(src: str) -> int:
    """Rough McCabe number — count of decision points + 1 per contract."""
    return len(_BRANCH_KWS_RE.findall(src)) + len(_LOGIC_OP_RE.findall(src)) + 1


def _function_bodies(src: str) -> list[tuple[str, str]]:
    """Return (header_modifiers, body) for each `function name(...){...}` def.

    The body is brace-matched from the opening `{` of the function. Only
    functions WITH a body match (`_FUNC_DEF_RE` requires the brace) — interface
    declarations like `function foo() external;` are skipped, which is what we
    want for branch counting. Whole-file scope (multiple contracts in one source
    are all counted), consistent with `cyclomatic_complexity`.
    """
    out: list[tuple[str, str]] = []
    n = len(src)
    for m in _FUNC_DEF_RE.finditer(src):
        header = m.group(2)        # modifiers between ')' and '{'
        i = m.end()                # just past the opening '{'
        depth = 1
        while i < n and depth > 0:
            c = src[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        body = src[m.end(): i - 1] if depth == 0 else src[m.end(): i]
        out.append((header, body))
    return out


def _branches_in(text: str) -> int:
    """Decision points inside a single function body (no +1 baseline)."""
    return len(_BRANCH_KWS_RE.findall(text)) + len(_LOGIC_OP_RE.findall(text))


def _gini(values: list[float]) -> float:
    """Gini concentration of a non-negative list. 0 = perfectly even,
    →1 = all mass on one element. Returns 0 for empty / all-zero / singleton.
    """
    xs = sorted(float(v) for v in values)
    n = len(xs)
    if n < 2:
        return 0.0
    s = sum(xs)
    if s == 0:
        return 0.0
    cum = sum(i * x for i, x in enumerate(xs, start=1))
    return (2.0 * cum) / (n * s) - (n + 1.0) / n


def per_function_branch_stats(src: str) -> dict[str, Any]:
    """Decompose contract complexity into per-function branch counts.

    `cyclomatic_complexity` is a whole-contract sum; it can't separate
    'many shallow functions' (random-fuzz territory) from 'few deep functions'
    (LLM-reasoning territory). These features expose that distribution:
      total_fn_count        — all function definitions (with bodies)
      payable_fn_count      — functions whose header declares `payable`
      max_branches_per_fn   — the single hardest function's branch count
      avg_branches_per_fn   — mean branches per function
      branch_gini           — concentration of branches across functions
                              (high = one hot function amid simple ones)
    """
    bodies = _function_bodies(src)
    counts = [_branches_in(b) for _, b in bodies]
    n_fn = len(bodies)
    n_payable = sum(1 for head, _ in bodies if re.search(r"\bpayable\b", head))
    return {
        "total_fn_count":      n_fn,
        "payable_fn_count":    n_payable,
        "max_branches_per_fn": max(counts) if counts else 0,
        "avg_branches_per_fn": (sum(counts) / n_fn) if n_fn else 0.0,
        "branch_gini":         _gini([float(c) for c in counts]),
    }


def inheritance_depth(src: str) -> int:
    """Max number of bases on any contract definition (single-file scope)."""
    depths = []
    for m in _CONTRACT_RE.finditer(src):
        bases = m.group(2) or ""
        depths.append(len([b for b in bases.split(",") if b.strip()]))
    return max(depths) if depths else 0


def extract_pragma(src: str) -> str:
    m = _PRAGMA_RE.search(src)
    return m.group(1).strip() if m else "unknown"


def _external_fn_count_from_source(src_no_comments: str) -> int:
    """Source-regex fallback for the external/public state-mutating surface,
    used when no ABI is available (the entire SmartBugs dataset compiles at
    fuzz-time, so `extract_all` is called with abi=None there). A function
    counts iff its header is not internal/private and not view/pure. Solidity
    <0.5 functions with no explicit visibility default to public → counted.
    """
    count = 0
    for head, _ in _function_bodies(src_no_comments):
        if re.search(r"\b(internal|private)\b", head):
            continue
        if re.search(r"\b(view|pure|constant)\b", head):
            continue
        count += 1
    return count


def extract_group1(src: str, src_no_comments: str, abi: list[dict] | None) -> dict[str, Any]:
    n_ext_fn = (
        sum(1 for f in (abi or []) if f.get("type") == "function"
            and f.get("stateMutability") not in ("view", "pure"))
        if abi else _external_fn_count_from_source(src_no_comments)
    )
    return {
        "loc": loc(src_no_comments),
        "external_fn_count": n_ext_fn,
        "cyclomatic_complexity": cyclomatic_complexity(src_no_comments),
        **per_function_branch_stats(src_no_comments),
        "inheritance_depth": inheritance_depth(src_no_comments),
        "import_count": len(_IMPORT_RE.findall(src_no_comments)),
        "library_use_count": len(_LIB_USE_RE.findall(src_no_comments)),
        "solidity_pragma": extract_pragma(src),
    }


# ── Group 2: DeFi & fund-flow characteristics ─────────────────────────────────

# Patterns are NAME-based — capture the most common DeFi vocabulary across
# our DeFiHackLabs corpus. Case-insensitive to catch BalancerV2, AAVE3, etc.
_DEFI_ACTION_PATTERNS = {
    "swap":       r"\bswap\w*\s*\(",
    "transfer":   r"\b(?:transfer|transferFrom|safeTransfer)\s*\(",
    "flashloan":  r"\b(?:flashLoan|flashloan|flashLend)\w*\s*\(",
    "liquidity":  r"\b(?:addLiquidity|removeLiquidity)\w*\s*\(",
    "burn":       r"\b(?:_burn|burn|burnFrom)\s*\(",
    "mint":       r"\b(?:_mint|mint|mintTo)\s*\(",
    "deposit":    r"\b(?:deposit|stake|bond)\w*\s*\(",
    "withdraw":   r"\b(?:withdraw|unstake|unbond|claim|harvest)\w*\s*\(",
}

_ORACLE_RE  = re.compile(r"\b(?:oracle|getPrice|latestAnswer|priceFeed|AggregatorV3)\b", re.I)
_UNISWAP_RE = re.compile(r"\b(?:IUniswap|UniswapV[23]|getReserves|pair|router)\w*\b", re.I)
_FLASH_RE   = re.compile(r"\b(?:flashLoan|flashloan|IERC3156|onFlashLoan)\b", re.I)
_MOD_USE_RE = re.compile(r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyOperator|whenNotPaused|nonReentrant)\b")
_FUNC_DEF_RE = re.compile(r"function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\{", re.S)


def _uncontrolled_token_ops(src: str) -> int:
    """Count of (mint|burn|transfer*) function definitions WITHOUT any
    onlyOwner-style modifier in the function header."""
    count = 0
    for m in _FUNC_DEF_RE.finditer(src):
        name = m.group(1).lower()
        head = m.group(2)
        if any(k in name for k in ("mint", "burn", "transfer")):
            if not _MOD_USE_RE.search(head):
                count += 1
    return count


def extract_group2(src_no_comments: str) -> dict[str, Any]:
    actions = {f"defi_{k}_count": len(re.findall(p, src_no_comments, flags=re.I))
               for k, p in _DEFI_ACTION_PATTERNS.items()}
    total_defi = sum(actions.values())
    return {
        **actions,
        "defi_action_count_total": total_defi,
        "has_oracle":      bool(_ORACLE_RE.search(src_no_comments)),
        "has_uniswap":     bool(_UNISWAP_RE.search(src_no_comments)),
        "has_flashloan":   bool(_FLASH_RE.search(src_no_comments)),
        "access_control_modifier_uses": len(_MOD_USE_RE.findall(src_no_comments)),
        "uncontrolled_token_op_count":  _uncontrolled_token_ops(src_no_comments),
    }


# ── Group 3: State & constraint features ─────────────────────────────────────

_HEX_ADDR_RE     = re.compile(r"0x[0-9a-fA-F]{40}\b")
_BIG_NUMERAL_RE  = re.compile(r"\b\d{6,}\b|\b1e\d+\b")   # 6+ digit decimals or scientific notation
_TIMESTAMP_RE    = re.compile(r"\bblock\.timestamp\b|\bnow\b")
_BLOCKNUM_RE     = re.compile(r"\bblock\.number\b")
_REENT_GUARD_RE  = re.compile(r"\b(?:nonReentrant|ReentrancyGuard)\b")
_REQUIRE_RE      = re.compile(r"\brequire\s*\(")
_ASSERT_RE       = re.compile(r"\bassert\s*\(")


def extract_group3(src_no_comments: str, src_loc: int) -> dict[str, Any]:
    n_require = len(_REQUIRE_RE.findall(src_no_comments))
    n_assert  = len(_ASSERT_RE.findall(src_no_comments))
    return {
        "hardcoded_address_count": len(_HEX_ADDR_RE.findall(src_no_comments)),
        "magic_number_count":      len(_BIG_NUMERAL_RE.findall(src_no_comments)),
        "uses_timestamp":          bool(_TIMESTAMP_RE.search(src_no_comments)),
        "uses_blocknum":           bool(_BLOCKNUM_RE.search(src_no_comments)),
        "has_reentrancy_guard":    bool(_REENT_GUARD_RE.search(src_no_comments)),
        "require_count":           n_require,
        "assert_count":            n_assert,
        "constraint_density":      (n_require + n_assert) / max(1, src_loc),
    }


# ── Top-level ─────────────────────────────────────────────────────────────────

def extract_all(src: str, abi: list[dict] | None = None) -> dict[str, Any]:
    """Extract all Group 1+2+3 features from a single source string."""
    src_nc = strip_comments(src)
    src_loc = loc(src_nc)
    return {
        **extract_group1(src, src_nc, abi),
        **extract_group2(src_nc),
        **extract_group3(src_nc, src_loc),
    }
