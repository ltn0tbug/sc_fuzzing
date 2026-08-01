"""Source/ABI text budgeting for LLM prompts — split out of `agent.py`.

Pure text helpers (regex only, no client/backend state): minify Solidity,
render compact ABI signatures, AST-slice the target contract, and apply the
three-stage source budget. `agent.py` re-exports these, so
`from ..llm.agent import minify_solidity` etc. keep working.
"""

import re


def _truncate_prompt(prompt: str, max_code_chars: int = 300) -> str:
    """Truncate long ```code``` blocks in a prompt for readable debug display."""
    def _trunc(m: re.Match) -> str:
        s = m.group(0)
        nl = s.find("\n") + 1
        header, body = s[:nl], s[nl:]
        if len(body) > max_code_chars:
            return header + body[:max_code_chars] + f"\n... [{len(body) - max_code_chars} more chars]\n```"
        return s
    return re.sub(r"```[^\n]*\n[\s\S]*?```", _trunc, prompt)


# ── Source minification + budget ──────────────────────────────────────────────
# Used by both `_LLMClient.build_contract_context` (gen/mut prompts) and by
# MADFuzz's seed-pool template. Some SmartBugs contracts have absurdly inflated
# inline whitespace (e.g. WhaleGiveaway2 has 1000+ space runs inside function
# bodies) and rambling comment blocks. Stripping them is a cheap pre-LLM win.
# Naive about strings — `//` or `/*` inside a Solidity string literal would be
# stripped — but that's vanishingly rare in real contracts and acceptable for
# prompt context.

_BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")
_LINE_COMMENT_RE  = re.compile(r"//[^\n]*")
_TAB_SPACE_RUN_RE = re.compile(r"[ \t]+")
_LINE_LEAD_WS_RE  = re.compile(r"\n[ \t]+")
_LINE_TAIL_WS_RE  = re.compile(r"[ \t]+\n")
_BLANK_LINES_RE   = re.compile(r"\n{3,}")


def minify_solidity(src: str) -> str:
    """Strip Solidity comments + collapse whitespace.

    Best-effort: doesn't tokenize, so `//` or `/* */` *inside* a string literal
    would be stripped. Real contracts almost never embed those, and the LLM
    only consumes this as prompt context, so the trade-off is fine.
    """
    src = _BLOCK_COMMENT_RE.sub("", src)
    src = _LINE_COMMENT_RE.sub("", src)
    src = _TAB_SPACE_RUN_RE.sub(" ", src)
    src = _LINE_LEAD_WS_RE.sub("\n", src)
    src = _LINE_TAIL_WS_RE.sub("\n", src)
    src = _BLANK_LINES_RE.sub("\n\n", src)
    return src.strip()


def format_abi_signatures(abi: list[dict]) -> str:
    """Render the target ABI's functions as a compact signature list for the
    whitebox prompt. Gives the model exact names, parameter types, arity, and
    mutability (payable/view/pure) so it doesn't have to recover them by parsing
    the Solidity source. Non-function entries (constructor/event/error/fallback)
    are skipped; nonpayable mutability is left untagged (the default)."""
    lines: list[str] = []
    for m in abi or []:
        if m.get("type", "function") != "function":
            continue
        name = m.get("name")
        if not name:
            continue
        ins = ", ".join(
            (f"{i.get('type', '')} {i.get('name')}".strip() if i.get("name") else i.get("type", ""))
            for i in m.get("inputs", [])
        )
        outs = ", ".join(o.get("type", "") for o in m.get("outputs", []))
        mut = m.get("stateMutability", "")
        tag = f"  [{mut}]" if mut in ("payable", "view", "pure") else ""
        lines.append(f"- {name}({ins})" + (f" -> {outs}" if outs else "") + tag)
    return "\n".join(lines)


def extract_target_contract_source(src: str, ast: dict, target_name: str) -> str | None:
    """Slice the source down to just the target contract + its in-file inherited
    bases + the file header (pragma, license, imports, file-level `using` directives).

    Returns the concatenated source slices, or None if the target isn't a
    `ContractDefinition` in this AST (e.g., wrong file, unrecognized name).

    The slicing uses byte offsets from each AST node's `src` field, so we copy
    actual original source text — no re-printing, no formatting loss.
    """
    if not ast or not target_name:
        return None
    nodes = ast.get("nodes", [])
    contracts_by_name = {
        n.get("name"): n
        for n in nodes
        if n.get("nodeType") == "ContractDefinition"
    }
    if target_name not in contracts_by_name:
        return None

    # Transitively collect base contract names defined in THIS file.
    # (Bases defined in imported files are left to the import statement.)
    wanted: set[str] = {target_name}
    queue = [target_name]
    while queue:
        cur = queue.pop()
        for b in contracts_by_name[cur].get("baseContracts", []):
            name_node = b.get("baseName", {})
            base_name = name_node.get("name") or (name_node.get("pathNode") or {}).get("name")
            if base_name and base_name in contracts_by_name and base_name not in wanted:
                wanted.add(base_name)
                queue.append(base_name)

    keep_ranges: list[tuple[int, int]] = []
    for n in nodes:
        nt = n.get("nodeType")
        keep = nt in ("PragmaDirective", "ImportDirective", "UsingForDirective") or (
            nt == "ContractDefinition" and n.get("name") in wanted
        )
        if not keep:
            continue
        try:
            off, ln, _fid = n.get("src", "0:0:0").split(":")
            keep_ranges.append((int(off), int(ln)))
        except (ValueError, AttributeError):
            continue
    if not keep_ranges:
        return None
    keep_ranges.sort()
    return "\n\n".join(src[off:off + ln] for off, ln in keep_ranges)


def apply_source_budget(
    src: str,
    max_chars: int,
    *,
    ast: dict | None = None,
    target_name: str | None = None,
) -> str:
    """Three-stage source budget pipeline for LLM context:

      1. Minify (strip comments, collapse whitespace). **Runs unconditionally —
         even when source is already under the cap.** This matters for fairness
         vs the RL-only baselines: the SmartBugs dataset embeds vulnerability
         hints in comments (`// <yes> <report> ARITHMETIC`, etc.). Shipping
         raw source would leak those hints to the LLM but not to baselines.
      2. If still over budget AND AST + target name available, extract the
         target contract + its in-file inherited bases, then re-minify.
         Drops sibling contracts/libraries/interfaces the LLM doesn't need
         to fuzz the target.
      3. If still over budget, truncate with a `// … [truncated N chars]` marker.

    `max_chars <= 0` disables only stages 2 & 3 (the size-check + extract +
    truncate). **Stage 1 (minify) always runs.**

    Empirically on SmartBugs-curated: stage 1 alone fits 82/83 contracts under
    a 12K cap; stage 2 saves ~35% on the 38/83 multi-contract files; stage 3
    catches only the lone 96K-char single-contract giant.
    """
    minified = minify_solidity(src)
    if max_chars <= 0 or len(minified) <= max_chars:
        return minified

    # Stage 2: AST-driven target extraction.
    if ast is not None and target_name:
        extracted = extract_target_contract_source(src, ast, target_name)
        if extracted is not None:
            extracted_min = minify_solidity(extracted)
            if len(extracted_min) <= max_chars:
                return (
                    extracted_min
                    + "\n// … [sibling contracts/interfaces in this file omitted]"
                )
            # Still too large — truncate the extracted version (it's already
            # smaller than the full minified source, so we lose less to the cut).
            dropped = len(extracted_min) - max_chars
            return (
                extracted_min[:max_chars]
                + f"\n// … [extracted target; truncated {dropped} chars] …"
            )

    # Stage 3: plain truncate.
    dropped = len(minified) - max_chars
    return minified[:max_chars] + f"\n// … [truncated {dropped} chars] …"
