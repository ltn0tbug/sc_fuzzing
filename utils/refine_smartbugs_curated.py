"""SmartBugs Curated drainability analyzer.

Decides whether each contract has at least one *attacker-reachable*
ETH-out path that can fire BUG_SIGNAL: target_drained or attacker_gained.

Output classification per contract:
  drain_msg_sender    — function sends ETH to msg.sender, publicly callable
  drain_arbitrary     — function sends ETH to an address parameter
  drain_selfdestruct  — function calls selfdestruct/suicide with attacker-controllable target
  drain_reentrancy    — ETH-out before state update (reentrancy attacker can drain)
  no_eth_path         — no path reaches an attacker-controllable destination
  blocked_by_auth     — has ETH-out but every path is gated by auth the attacker can't bypass
                        (still KEEP if category is access_control — auth IS the bug)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]   # repo root
DS = json.load(open(ROOT / 'utils/legacy_intermediate/smartbugs-curated.json'))
SB_ROOT = ROOT / 'ref/smartbugs-curated'

# ── Preprocessing ───────────────────────────────────────────────────────────

_BLOCK_C = re.compile(r"/\*[\s\S]*?\*/")
_LINE_C  = re.compile(r"//[^\n]*")

def strip_comments(s: str) -> str:
    return _LINE_C.sub("", _BLOCK_C.sub("", s))

# ── Function parsing (best-effort regex; SmartBugs contracts are simple) ────

_FUNC_HEAD_RE = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*?)\{",
    re.S,
)

def _find_function_bodies(src: str):
    """Yield (name, header_text, body_text) for each function.
    Body extraction uses simple brace-depth counting."""
    for m in _FUNC_HEAD_RE.finditer(src):
        name = m.group(1)
        params = m.group(2)
        header = m.group(3) or ""
        start = m.end() - 1  # at the opening brace
        depth = 0
        i = start
        while i < len(src):
            ch = src[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    body = src[start + 1: i]
                    yield name, params, header, body
                    break
            i += 1


# ── Visibility + auth detection ─────────────────────────────────────────────

_AUTH_MODS_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyOperator|onlyGovernance|onlyManager|"
    r"onlyAuthorized|onlyRole|onlyMinter|onlyBy|isOwner|requireOwner|"
    r"whenNotPaused|nonReentrant|hasRole|permitted|authorized)\b",
)

_AUTH_INLINE_RE = re.compile(
    r"\brequire\s*\(\s*(?:msg\.sender\s*==|tx\.origin\s*==)",
)

def _is_publicly_callable(header: str, body: str) -> bool:
    """A function is publicly callable if it's external/public AND has no
    attacker-blocking auth check in modifiers OR header inline."""
    if "external" not in header and "public" not in header:
        # private/internal/missing visibility (legacy: defaults to public)
        if any(kw in header for kw in ("private", "internal")):
            return False
    return True


def _has_auth_gate(header: str, body: str) -> bool:
    """True if function header or body contains an auth check the attacker
    can't satisfy. Returns False for access-control-bug contracts where the
    check is intentionally bypassable — we treat those contracts specially."""
    if _AUTH_MODS_RE.search(header):
        return True
    # Look only at the first ~5 lines of body for an early-return require
    head_body = "\n".join(body.splitlines()[:8])
    if _AUTH_INLINE_RE.search(head_body):
        return True
    return False


# ── ETH-out pattern detection ───────────────────────────────────────────────

# msg.sender direct destination
_ETH_TO_MSGSENDER = re.compile(
    r"(?:msg\.sender|tx\.origin)\s*\.(?:call\s*\.?\s*value\s*\(|call\s*\{[^}]*\}\s*\(|transfer\s*\(|send\s*\()",
)
_ETH_TO_MSGSENDER_LOW = re.compile(
    r"(?:msg\.sender|tx\.origin)\.call\.value\s*\(",
)

# Arbitrary address parameter (we check the params list)
_ADDR_TO_PARAM = re.compile(
    r"(\w+)\s*\.\s*(?:call\s*\.?\s*value|call\s*\{[^}]*\}|transfer|send)\s*\(",
)

_SELFDESTRUCT_RE = re.compile(r"\b(?:selfdestruct|suicide)\s*\(\s*([^)]+)\)")

# Reentrancy hint: ETH-out happens before any state assignment in the body
_STATE_WRITE_RE = re.compile(r"\b(?:\w+)\s*(?:\[\s*[^\]]+\s*\])?\s*=\s*[^=]")


_BALANCE_OUT_RE = re.compile(
    r"\.\s*(?:call\s*\.?\s*value|call\s*\{[^}]*value[^}]*\}|transfer|send)\s*\(\s*"
    r"(?:address\s*\(\s*this\s*\)\s*\.\s*balance|this\.balance)",
)
# this.balance / address(this).balance flowing through *any* call destination —
# captures "owner.transfer(this.balance)" and similar full-drain patterns

_OWNER_SETTER_RE = re.compile(
    r"\b(?:owner|admin|controller|operator|manager|creator|master|ceo|cfo|coo|founder)\s*=\s*msg\.sender",
)
# pattern that lets attacker take over storage-controlled drain destination


def _classify_function(name: str, params: str, header: str, body: str,
                       category: str) -> list[str]:
    """Return a list of drain-pattern tags this function exhibits.

    For access_control category, we ignore auth gates (the gate IS the bug)
    AND we look for ETH-out to storage-controlled addresses that the attacker
    can hijack via a separate broken-constructor / owner-setter call.

    For reentrancy category, we tag drain_reentrancy when ETH-out precedes state writes.
    """
    tags = []
    pub = _is_publicly_callable(header, body)
    if not pub:
        return []

    # Auth check — except for access_control category where it's bypassable
    gated = _has_auth_gate(header, body) and category != "access_control"

    # ── Pattern: full-balance external leak (drains target via address(this).balance) ──
    # Even if destination isn't attacker-controllable, BUG_SIGNAL: target_drained fires
    # when target's ETH balance drops >20%. A function that ships address(this).balance
    # to anywhere (including a hardcoded address) triggers this.
    if _BALANCE_OUT_RE.search(body) and not gated:
        tags.append("drain_external_leak")

    # ── Pattern: ETH-to-msg.sender (direct attacker drain) ──
    if _ETH_TO_MSGSENDER.search(body) or _ETH_TO_MSGSENDER_LOW.search(body):
        if not gated:
            tags.append("drain_msg_sender")
            # Check for reentrancy pattern (ETH out before state write)
            if category == "reentrancy":
                eth_pos = min(
                    [m.start() for m in _ETH_TO_MSGSENDER.finditer(body)] +
                    [m.start() for m in _ETH_TO_MSGSENDER_LOW.finditer(body)],
                    default=10**9,
                )
                sw_pos = min(
                    [m.start() for m in _STATE_WRITE_RE.finditer(body)],
                    default=10**9,
                )
                if eth_pos < sw_pos:
                    tags.append("drain_reentrancy")
        else:
            tags.append("blocked_by_auth")

    # ── Pattern: ETH-to-arbitrary-address-parameter ──
    param_names = re.findall(r"address(?:\s+payable)?\s+(\w+)", params)
    for m in _ADDR_TO_PARAM.finditer(body):
        target = m.group(1)
        if target in param_names and target not in ("msg", "tx", "address", "this"):
            if not gated:
                tags.append("drain_arbitrary")
                break

    # ── Pattern: selfdestruct ──
    for m in _SELFDESTRUCT_RE.finditer(body):
        target = m.group(1).strip()
        if not gated:
            if "msg.sender" in target or "tx.origin" in target:
                tags.append("drain_selfdestruct")
                break
            if target.split()[0] in param_names:
                tags.append("drain_selfdestruct")
                break
            tags.append("drain_selfdestruct")
            break

    # ── Pattern: owner-storage drain via broken access control ──
    # access_control category contracts often have a broken owner-setter (e.g.
    # incorrect_constructor_name) plus an onlyowner withdraw that ships balance
    # to `owner` storage. Once attacker hijacks owner via the broken setter, the
    # otherwise-auth-gated withdraw becomes a drain.
    # Detect: contract has an unprotected owner-setter elsewhere AND this function
    # transfers balance to a storage-controlled address.
    # (We tag at contract level after the function pass — see analyze() below.)

    return tags


# ── Per-contract analysis ───────────────────────────────────────────────────

_CONTRACT_NAMES_RE = re.compile(r"contract\s+(\w+)")


def _broken_constructor_function(src_nc: str, all_function_bodies):
    """Detect a 'broken constructor' — a public/external function that sets
    `owner = msg.sender` (or aliased: creator, admin, controller, …) without
    any auth gate AND whose name doesn't match a contract name in this file.

    Returns the function name if found, else None.

    Solidity 0.4 used `function ContractName() { … }` for constructors. When
    devs typo'd the name, the function became publicly callable. SmartBugs
    has many examples — `incorrect_constructor_name*`, `rubixi`,
    `initTokenBank`, etc. Once attacker calls this, they own the contract,
    so any subsequent `onlyOwner`-gated drain becomes attacker-drainable.
    """
    contract_names = set(_CONTRACT_NAMES_RE.findall(src_nc))
    for name, header, body in all_function_bodies:
        if not _is_publicly_callable(header, body):
            continue
        if _has_auth_gate(header, body):
            continue
        if name in contract_names:           # true 0.4-style constructor
            continue
        if name in ("constructor", "fallback", "receive"):
            continue
        if _OWNER_SETTER_RE.search(body):
            return name
    return None


def analyze(src: str, category: str) -> dict:
    src_nc = strip_comments(src)
    fn_tags = []
    all_function_bodies = []
    for name, params, header, body in _find_function_bodies(src_nc):
        all_function_bodies.append((name, header, body))
        tags = _classify_function(name, params, header, body, category)
        if tags:
            fn_tags.append((name, tags))

    # ── Contract-level: broken-constructor → universal auth bypass ──
    # If any function lets attacker take ownership without auth, then every
    # `onlyOwner`-gated drain function is effectively un-gated via the 2-call
    # sequence (init/broken-ctor → drain). Re-classify accordingly.
    bcs = _broken_constructor_function(src_nc, all_function_bodies)
    if bcs is not None:
        for n, params, header, body in [
            (a, b, c, d) for a, b, c, d
            in [(an, ap, ah, ab) for an, ap, ah, ab
                in _find_function_bodies(src_nc)]
        ]:
            # Re-classify with category forced to access_control (suppresses gating)
            extra_tags = _classify_function(n, params, header, body,
                                             category="access_control")
            # Only keep newly-found drain patterns (avoid duplicates)
            existing = {t for an, ts in fn_tags if an == n for t in ts}
            new_drains = [t for t in extra_tags
                          if t.startswith("drain_") and t not in existing]
            if new_drains:
                fn_tags.append((n, new_drains + ["drainable_via_broken_ctor"]))

    # ── Contract-level: owner-storage drain ──
    has_broken_owner_setter = bcs is not None or any(
        _OWNER_SETTER_RE.search(body) and not _has_auth_gate(header, body)
        for _, header, body in all_function_bodies
    )
    if has_broken_owner_setter:
        for n, h, b in all_function_bodies:
            if re.search(r"\b(?:owner|admin|controller|operator|manager|creator)\s*\.\s*"
                          r"(?:transfer|send|call\s*\.?\s*value|call\s*\{)", b):
                fn_tags.append((n, ["drain_owner_hijack"]))

    # Collect global pattern set
    all_tags = {t for _, ts in fn_tags for t in ts}
    drain_tags = {t for t in all_tags if t.startswith("drain_")}
    return {
        "drain_paths": sorted(drain_tags),
        "functions_with_drain": sorted({n for n, ts in fn_tags
                                  if any(t.startswith("drain_") for t in ts)}),
        "functions_blocked": [n for n, ts in fn_tags
                              if "blocked_by_auth" in ts and not any(t.startswith("drain_") for t in ts)],
        "broken_constructor": bcs,
        "drainable": len(drain_tags) > 0,
    }


# ── Driver ──────────────────────────────────────────────────────────────────

def main():
    results = []
    for c in DS["contracts"]:
        # Read source from the source_code field if present, else from path
        src = c.get("source_code", "")
        if not src and "path" in c:
            p = SB_ROOT / c["path"]
            if p.exists():
                src = p.read_text(errors="replace")
        if not src:
            results.append({**c, "_analysis": {"drainable": False, "drain_paths": [], "functions_with_drain": [], "error": "no source"}})
            continue
        ana = analyze(src, c["category"])
        results.append({"id": c["id"], "category": c["category"],
                        "currently_skipped": bool(c.get("skip")),
                        "skip_reason_existing": c.get("skip_reason"),
                        **ana})
    return results


if __name__ == "__main__":
    out = main()
    # Print summary
    drainable = [r for r in out if r["drainable"]]
    not_drainable = [r for r in out if not r["drainable"] and not r.get("currently_skipped")]
    already_skipped = [r for r in out if r.get("currently_skipped")]
    print(f"Total contracts: {len(out)}")
    print(f"  Drainable:           {len(drainable):>3}")
    print(f"  Not drainable (kept): {len(not_drainable):>3}")
    print(f"  Already skipped:     {len(already_skipped):>3}")
    print()
    # Per-category breakdown
    from collections import Counter
    cat_drainable = Counter()
    cat_total = Counter()
    for r in out:
        cat_total[r["category"]] += 1
        if r["drainable"]:
            cat_drainable[r["category"]] += 1
    print(f"Per category:")
    for cat in sorted(cat_total):
        print(f"  {cat:<28} {cat_drainable[cat]:>3}/{cat_total[cat]:>3} drainable")

    # Drain-path breakdown
    path_counts = Counter()
    for r in out:
        for p in r["drain_paths"]:
            path_counts[p] += 1
    print(f"\nDrain-path frequency:")
    for p, n in path_counts.most_common():
        print(f"  {p}: {n}")

    # The danger cases: contracts currently in usable BUT not drainable
    cur_keep_not_drainable = [r for r in out if not r["drainable"] and not r.get("currently_skipped")]
    print(f"\n=== Currently in usable but NOT drainable ({len(cur_keep_not_drainable)}) — candidates to remove ===")
    for r in cur_keep_not_drainable[:30]:
        print(f"  {r['category']:<28} {r['id'].split('/')[-1][:50]}")
    if len(cur_keep_not_drainable) > 30:
        print(f"  ... and {len(cur_keep_not_drainable) - 30} more")

    # Validation: contracts that found bugs should ALL be classified drainable
    bug_found_ids = json.load(open('/tmp/sb_bug_found_ids.json')) if Path('/tmp/sb_bug_found_ids.json').exists() else None
    if bug_found_ids:
        misses = [r for r in out if r['id'] in bug_found_ids and not r['drainable']]
        print(f"\n=== Validation misses (bug found but classified not-drainable): {len(misses)} ===")
        for r in misses:
            print(f"  {r['id']}: {r.get('drain_paths')}, blocked: {r.get('functions_blocked')}")

    # Save full analysis to JSON for review
    Path('/tmp/sb_drainability.json').write_text(json.dumps(out, indent=2))
    print(f"\nFull analysis: /tmp/sb_drainability.json")
