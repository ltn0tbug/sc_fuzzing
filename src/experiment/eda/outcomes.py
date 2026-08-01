"""Outcome (Group 4) extraction from run-log JSONs.

Reads the per-contract result files written by src/experiment/run/run.py
and returns a flat dict per (dataset, method, contract) tuple:

    bugs_found                int     - total_bugs_found
    bc_coverage_ratio         float   - bytecode-level branch coverage hit ratio
    new_bc_branches           int     - cumulative new branches discovered
    iter_first_bug            int     - 0-indexed iteration at which the first bug appeared
                                        (None if no bug found)
    total_iterations          int     - actual iters that ran (may be < MAX_ITERATIONS on crash)
    tokens_total              int     - LLM tokens spent (0 for rlfuzz)
    random_inputs_used        int     - ε-greedy random iterations (sscfuzz only; 0 elsewhere)
    detection_category        str     - hash-keyed bucket from bug type strings,
                                        used as the categorical Y in Group 4

This module is dataset/method-agnostic — the joiner threads dataset/method
labels in as columns.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _iter_first_bug(iterations: list[dict]) -> int | None:
    """Find the earliest iteration index containing a bug-marker.

    Logs from the three methods use slightly different shapes:
      sscfuzz : iteration["fuzzing_output"]["new_bc_branches"]>0 doesn't imply bug —
                check iteration["fuzzing_output"]["bug_found"] or .raw_reason if present
      rlfuzz  : iteration["bug_found"] is the boolean
      madfuzz : iteration["bug_found"] / iteration["bug_type"] is the marker
    We look for any of these signals.
    """
    for it in iterations:
        if not isinstance(it, dict):
            continue
        # Direct boolean
        if it.get("bug_found") or it.get("bug_type"):
            return it.get("iteration", it.get("iter"))
        # sscfuzz nests inside fuzzing_output
        fo = it.get("fuzzing_output") or {}
        if isinstance(fo, dict) and (fo.get("bug_found") or fo.get("found_bug")):
            return it.get("iteration", it.get("iter"))
    return None


def _sequence_diversity(iterations: list[dict]) -> float:
    """Mean Jaccard *distance* between consecutive iterations' call-name sets.

    Measures exploration behaviour, not outcome: each iteration's fuzz_input
    is a list of calls `[name, args, value, caller]`; the set of `name`s is the
    iteration's footprint. 1.0 = every step targets entirely different
    functions (broad, uniform — random-fuzz signature); →0 = the fuzzer keeps
    hammering the same functions (locked-in exploitation). Returns 0.0 when
    fewer than two usable iterations exist.
    """
    name_sets: list[frozenset[str]] = []
    for it in iterations:
        if not isinstance(it, dict):
            continue
        fi = it.get("fuzz_input") or {}
        calls = fi.get("calls") if isinstance(fi, dict) else None
        if not isinstance(calls, list):
            continue
        names = {c[0] for c in calls if isinstance(c, (list, tuple)) and c}
        name_sets.append(frozenset(names))
    if len(name_sets) < 2:
        return 0.0
    dists: list[float] = []
    for a, b in zip(name_sets, name_sets[1:]):
        union = a | b
        if not union:
            continue  # both empty — undefined, skip
        inter = a & b
        dists.append(1.0 - len(inter) / len(union))
    return sum(dists) / len(dists) if dists else 0.0


def _detection_category(bugs: list[dict]) -> str:
    """Collapse bug-type strings into one of:
       drain | reentrancy | overflow | access | imbalance | other | none
    """
    if not bugs:
        return "none"
    types: set[str] = set()
    for b in bugs:
        if not isinstance(b, dict):
            continue
        for key in ("bug_type", "type", "category"):
            v = b.get(key)
            if isinstance(v, str):
                types.add(v.lower())
        # decoded_logs may contain BUG_SIGNAL strings
        for log in b.get("decoded_logs", []) or []:
            if isinstance(log, str) and "BUG_SIGNAL" in log:
                types.add(log.split("BUG_SIGNAL:")[-1].strip().lower())
    txt = " ".join(types)
    # Net-profit-oracle vocabulary: target_loss/target_drained → drain;
    # attacker_profit/attacker_gained → access (value-extraction). Order matters —
    # check drain-side before the attacker-side so a row tagged with both lands in
    # drain (the more specific impact-on-target bucket), as before.
    if "mint" in txt:                                              return "mint"
    if "drain" in txt or "target_drained" in txt or "target_loss" in txt:
        return "drain"
    if "reentr" in txt:                                           return "reentrancy"
    if "overflow" in txt or "underflow" in txt:                   return "overflow"
    if "attacker_gained" in txt or "attacker_profit" in txt or "access" in txt:
        return "access"
    if "imbalance" in txt or "price" in txt:                      return "imbalance"
    return "other"


def extract_outcome(path: Path | str) -> dict[str, Any] | None:
    """Read one result JSON file. Returns None if file is unreadable / missing keys."""
    try:
        data = json.loads(Path(path).read_text())
    except Exception:
        return None
    summary = data.get("summary") or {}
    iters   = data.get("iterations") or []
    bugs    = data.get("bugs") or []

    out: dict[str, Any] = {
        "bugs_found":           int(summary.get("total_bugs_found", 0)),
        "bc_coverage_ratio":    float(summary.get("bc_coverage_ratio", 0.0)),
        "new_bc_branches":      int(summary.get("total_new_bc_branches", 0)),
        "total_bc_branches":    int(summary.get("total_bc_branches", 0)),
        "total_iterations":     int(summary.get("total_iterations", 0)),
        "total_reward":         float(summary.get("total_reward", 0.0)),
    }

    tok = summary.get("token_usage") or {}
    out["tokens_total"] = int(tok.get("total_tokens", 0)) if isinstance(tok, dict) else 0

    out["random_inputs_used"] = int(summary.get("random_inputs_used", 0))
    out["iter_first_bug"]     = _iter_first_bug(iters)
    out["detection_category"] = _detection_category(bugs)
    out["bug_found_any"]      = out["bugs_found"] > 0
    out["sequence_diversity"] = _sequence_diversity(iters)

    # Learning-process scalars (summary.learning_curve; see fuzz/report.py). Flat
    # per-contract columns so cross-method learning comparisons need no re-parse.
    # None-safe: older logs without the block leave these blank.
    lc = summary.get("learning_curve") or {}
    out["first_bug_iter"]           = lc.get("first_bug_iter")
    out["coverage_saturation_iter"] = lc.get("coverage_saturation_iter")
    out["final_epsilon"]            = lc.get("final_epsilon")            # RL methods only
    out["mean_loss_last_decile"]    = lc.get("mean_loss_last_decile")    # RL methods only
    return out


def safe_id_from_path(path: Path | str, prefix: str = "defihacklabs_") -> str:
    """Result files are named `<prefix><safe_id>.json` — strip both."""
    name = Path(path).stem
    if name.startswith(prefix):
        name = name[len(prefix):]
    return name
