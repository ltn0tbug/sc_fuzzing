"""Build the tidy EDA DataFrame.

One row per (dataset, contract_id). Columns:
  - identifiers: dataset, contract_id, category (smartbugs only)
  - Groups 1+2+3: static features from features.py
  - Group 4: per-method outcomes — bugs_found_<method>, bc_cov_<method>, ...

Methods covered: rlfuzz, madfuzz, sscfuzz, randomfuzz, llmfuzz, financefuzz.
Cells stay NaN where results haven't been generated yet — the joiner is
forward-compatible: re-run once any method's sweep finishes.

Dataset records come from the unified loader (src/experiment/dataloader/schema.py),
`load_all` (every contract, skip-flagged) with repo-relative source pointers into
data/<dataset>/source/ — ./ref is never read here.

Run as a script to print row counts; import as a module to get the DataFrame.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pandas as pd

from features import extract_all
from outcomes import extract_outcome

# ── Path constants ────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[3]      # src/experiment/eda → repo root
LOADER_DIR = ROOT / "src" / "experiment" / "dataloader"
RESULTS_DIR = ROOT / "output" / "experiment"   # ./output/experiment/<dataset>/<method>/

# Unified dataset loader (src/experiment/dataloader/schema.py). `load_all` returns a
# Contract per contract (skipped included) with repo-relative source pointers into
# data/<dataset>/source/ — we never read ./ref here.
sys.path.insert(0, str(LOADER_DIR))
from schema import load_all  # noqa: E402

METHODS = ("randomfuzz", "financefuzz", "rlfuzz", "madfuzz", "llmfuzz", "sscfuzz")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_source(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except Exception:
        return ""


def _safe_id(contract_id: str) -> str:
    """Strip the leading 'defihacklabs/' prefix from id."""
    return re.sub(r"^defihacklabs/", "", contract_id)


def _smartbugs_safe_id(contract_id: str) -> str:
    """SmartBugs ids look like 'reentrancy/0x...'. The result-file naming uses
    the address-with-extension stem. We map id → result-filename stem.
    """
    return contract_id.split("/")[-1]  # the 0x... part is the result filename


# ── SmartBugs readable names ──────────────────────────────────────────────────
# SmartBugs-curated files are named only by on-chain address (no human name in the
# metadata), so heatmap/table rows read as hex. The readable name lives in the source:
# the primary (largest-body) contract definition. These helpers resolve it so figures
# can label SmartBugs rows by contract name instead of address.

def _contract_defs(src: str) -> list[tuple[str, str, int]]:
    """(kind, name, body_len) for every top-level contract/library/interface, body_len
    measured by brace-matching from the opening `{`."""
    out = []
    for m in re.finditer(r"\b(contract|library|interface)\s+([A-Za-z_]\w*)", src):
        i = src.find("{", m.end())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((m.group(1), m.group(2), j - i))
    return out


def primary_contract_name(src: str) -> str | None:
    """The vulnerable/main contract of a SmartBugs source = the largest-body `contract`
    (helpers like Log/SafeMath/ERC20 are smaller); falls back to any library/interface."""
    defs = _contract_defs(src)
    contracts = [(n, ln) for k, n, ln in defs if k == "contract"] or [(n, ln) for _, n, ln in defs]
    if not contracts:
        return None
    return max(contracts, key=lambda x: x[1])[0]


def _stem_tag(stem: str) -> str:
    """A short disambiguator for a SmartBugs stem: the first 4 hex for an address
    (`0x23a9…` → `23a9`), else the trailing alphanumeric token of the filename
    (`wallet_03_wrong_constructor` → `constructor`)."""
    if stem.startswith("0x"):
        return stem[2:6]
    toks = re.findall(r"[A-Za-z0-9]+", stem)
    return toks[-1] if toks else stem


def smartbugs_display_names(maxlen: int = 20) -> dict[str, str]:
    """{result-file stem → readable label}. Label = the source's primary contract name,
    truncated to `maxlen`. When several contracts share a name (e.g. three `Wallet`s), a
    `·<tag>` disambiguator (see `_stem_tag`) is appended so rows stay unique; if that still
    collides, a running index is used as a last resort."""
    raw: dict[str, str | None] = {}
    for c in load_all("smartbugs"):
        stem = c.id.split("/")[-1]
        src = _read_source(ROOT / c.source.path) if c.source.path else ""
        raw[stem] = primary_contract_name(src) if src else None
    from collections import Counter
    counts = Counter((n or "").lower() for n in raw.values())

    def trunc(s: str) -> str:
        return s if len(s) <= maxlen else s[: maxlen - 1] + "…"

    out: dict[str, str] = {}
    used: set[str] = set()
    for stem, name in raw.items():
        if not name:
            label = trunc(stem)                                   # no parseable contract
        elif counts[name.lower()] > 1:
            tag = _stem_tag(stem)                                 # shared name → tag it,
            label = trunc(name) if tag.lower() == name.lower() else f"{trunc(name)}·{tag}"
        else:
            label = trunc(name)
        if label in used:                                        # last-resort uniqueness
            i = 2
            while f"{label} ({i})" in used:
                i += 1
            label = f"{label} ({i})"
        used.add(label)
        out[stem] = label
    return out


# ── Per-dataset loaders ───────────────────────────────────────────────────────

def _load_smartbugs() -> list[dict[str, Any]]:
    """Build raw rows for SmartBugs — one per contract.
    Each row has identifiers + static features. Outcomes are joined later.
    """
    rows = []
    for c in load_all("smartbugs"):
        src_path = ROOT / c.source.path
        src = _read_source(src_path)
        if not src:
            continue
        # No ABI for SmartBugs in our setup (compiled at fuzz-time)
        row = {
            "dataset": "smartbugs",
            "contract_id": c.id,
            "category": c.category,
            "name": c.provenance.get("name"),
            "src_loc_path": str(src_path),
            **extract_all(src, abi=None),
        }
        rows.append(row)
    return rows


def _load_defihacklabs() -> list[dict[str, Any]]:
    """Build raw rows for DeFiHackLabs — one per contract."""
    rows = []
    for c in load_all("defihacklabs"):
        # source.dir is repo-relative (e.g. data/defihacklabs/...).
        # Skipped/unfetched rows carry no source pointer (dir=None) — no source to analyze.
        if not c.source.dir:
            continue
        # Layout varies: some bundles have `src/`, others put .sol at the root.
        entry_root = ROOT / c.source.dir
        src_root = entry_root / "src" if (entry_root / "src").exists() else entry_root
        srcs = [_read_source(p) for p in src_root.rglob("*.sol")]
        src = "\n\n".join(s for s in srcs if s)
        if not src:
            continue
        abi_path = ROOT / c.source.abi_path if c.source.abi_path else None
        abi = json.loads(abi_path.read_text()) if abi_path and abi_path.exists() else None
        row = {
            "dataset": "defihacklabs",
            "contract_id": c.id,
            "category": c.category,            # DeFi-specific taxonomy (manifest)
            "name": c.target_contract,
            "chain": c.fork.chain if c.fork else None,
            "src_loc_path": str(src_root),
            **extract_all(src, abi=abi),
        }
        rows.append(row)
    return rows


# ── Outcome attach ────────────────────────────────────────────────────────────

def _outcome_path(dataset: str, method: str, contract_id: str) -> Path:
    """Locate the run-log JSON for a single (dataset, method, contract).

    Filename conventions (see src/experiment/run/run.py — `<contract.safe_id>.json`,
    safe_id = id.replace('/','_')):
      smartbugs:    output/experiment/smartbugs/<method>/<category>_<address>.json
      defihacklabs: output/experiment/defihacklabs/<method>/defihacklabs_<safe_id>.json
    """
    if dataset == "smartbugs":
        # id like "reentrancy/0x...".  Result file: <category>_<address>.json
        stem = contract_id.replace("/", "_")
        # Strip .sol suffix if present
        if stem.endswith(".sol"):
            stem = stem[:-4]
        return RESULTS_DIR / "smartbugs" / method / f"{stem}.json"
    if dataset == "defihacklabs":
        sid = _safe_id(contract_id)
        return RESULTS_DIR / "defihacklabs" / method / f"defihacklabs_{sid}.json"
    raise ValueError(f"unknown dataset: {dataset!r}")


def _attach_outcomes(row: dict[str, Any]) -> dict[str, Any]:
    """Attach per-method Group 4 outcome columns to a single row dict."""
    for method in METHODS:
        p = _outcome_path(row["dataset"], method, row["contract_id"])
        out = extract_outcome(p) if p.exists() else None
        if out is None:
            # Mark as missing — pandas will see these as NaN in numeric columns
            row[f"{method}__bugs_found"]        = float("nan")
            row[f"{method}__bc_cov"]            = float("nan")
            row[f"{method}__new_bc_branches"]   = float("nan")
            row[f"{method}__total_iterations"]  = float("nan")
            row[f"{method}__tokens_total"]      = float("nan")
            row[f"{method}__random_inputs"]     = float("nan")
            row[f"{method}__iter_first_bug"]    = float("nan")
            row[f"{method}__detection_category"] = "missing"
            row[f"{method}__bug_found_any"]     = False
            row[f"{method}__sequence_diversity"] = float("nan")
            row[f"{method}__result_available"]  = False
        else:
            row[f"{method}__bugs_found"]        = out["bugs_found"]
            row[f"{method}__bc_cov"]            = out["bc_coverage_ratio"]
            row[f"{method}__new_bc_branches"]   = out["new_bc_branches"]
            row[f"{method}__total_iterations"]  = out["total_iterations"]
            row[f"{method}__tokens_total"]      = out["tokens_total"]
            row[f"{method}__random_inputs"]     = out["random_inputs_used"]
            row[f"{method}__iter_first_bug"]    = (
                out["iter_first_bug"] if out["iter_first_bug"] is not None else float("nan")
            )
            row[f"{method}__detection_category"] = out["detection_category"]
            row[f"{method}__bug_found_any"]     = out["bug_found_any"]
            row[f"{method}__sequence_diversity"] = out["sequence_diversity"]
            row[f"{method}__result_available"]  = True
    return row


# ── Public API ────────────────────────────────────────────────────────────────

def build_dataframe() -> pd.DataFrame:
    """Build the tidy EDA DataFrame across both datasets."""
    rows = _load_smartbugs() + _load_defihacklabs()
    rows = [_attach_outcomes(r) for r in rows]
    df = pd.DataFrame(rows)
    return df


if __name__ == "__main__":
    df = build_dataframe()
    print(f"Total rows: {len(df)}")
    print(f"Datasets:   {df['dataset'].value_counts().to_dict()}")
    for m in METHODS:
        n_avail = int(df[f"{m}__result_available"].sum())
        print(f"  {m}: {n_avail} contracts with results")
    print()
    print(f"Columns ({len(df.columns)}):")
    for c in df.columns:
        print(f"  {c}")
