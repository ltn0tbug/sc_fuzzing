"""Build the legacy SmartBugs intermediate JSON from ref/smartbugs-curated/.

Writes legacy_intermediate/smartbugs-curated.json (gitignored staging) — the input
to restructure_datasets.py, which emits the canonical raw/manifest/enrich files.

Extracts every contract in the four target categories — reentrancy,
access_control, arithmetic, and unchecked_low_level_calls — together with all per-contract
metadata available in the source dataset, plus a few derived fields useful for
EDA (line count, byte size, declared contract names).

Source layout (read-only):
  ref/smartbugs-curated/
    dataset/<category>/<contract>.sol
    vulnerabilities.json   — per-contract vuln-line annotations + source URL
    versions.csv           — compiler-version mappings

Run:
  uv run python utils/build_smartbugs_curated.py

Output:
  utils/legacy_intermediate/smartbugs-curated.json   (gitignored staging)
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

# NOTE: emits the LEGACY per-dataset schema. After (re)building, run
# `utils/restructure_datasets.py`, which converts this legacy
# intermediate into the canonical raw/manifest/enrich files under
# data/smartbugs_curated/ (consumed by the dataloader schema.py).
ROOT = Path(__file__).resolve().parents[1]   # repo root (utils is 1 level deep)
SRC_DIR = ROOT / "ref" / "smartbugs-curated"
OUT_PATH = ROOT / "utils" / "legacy_intermediate" / "smartbugs-curated.json"

# We only care about four DASP categories for the current research round.
TARGET_CATEGORIES = ("reentrancy", "access_control", "arithmetic", "unchecked_low_level_calls")

SOURCE_REPO_URL = "https://github.com/smartbugs/smartbugs-curated"

# Match `contract Foo {`, `library Foo {`, `interface Foo {` to enumerate
# declared types in each file. Crude but works for the small contracts in this
# dataset; we are not running a Solidity parser here.
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def _load_versions_csv() -> dict[str, tuple[str, str]]:
    """Return {dataset/path.sol → (compiled_version, notes)} from versions.csv."""
    out: dict[str, tuple[str, str]] = {}
    csv_path = SRC_DIR / "versions.csv"
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            out[row["file"]] = (row.get("compiled version", "").strip(), row.get("notes", "").strip())
    return out


def _load_vulnerabilities() -> dict[str, dict]:
    """Return {path → entry dict} from vulnerabilities.json."""
    j = json.loads((SRC_DIR / "vulnerabilities.json").read_text())
    return {entry["path"]: entry for entry in j}


def _derive_id(rel_path: str) -> str:
    """Stable id: '<category>/<basename_without_ext>'. Hex addresses kept as-is."""
    p = Path(rel_path)
    return f"{p.parts[-2]}/{p.stem}"


def _extract_pragma_from_source(source: str) -> str:
    m = _PRAGMA_RE.search(source)
    return m.group(1).strip() if m else ""


def build() -> dict:
    versions = _load_versions_csv()
    vulns = _load_vulnerabilities()

    contracts: list[dict] = []
    per_cat = {c: 0 for c in TARGET_CATEGORIES}

    for category in TARGET_CATEGORIES:
        cat_dir = SRC_DIR / "dataset" / category
        if not cat_dir.is_dir():
            raise RuntimeError(f"Missing category directory: {cat_dir}")

        for sol_path in sorted(cat_dir.glob("*.sol")):
            rel_path = f"dataset/{category}/{sol_path.name}"
            source_code = sol_path.read_text(encoding="utf-8", errors="replace")
            v_entry = vulns.get(rel_path, {})
            compiled, notes = versions.get(rel_path, ("", ""))

            # Canonical pragma: prefer the source-extracted version (matches what
            # solc actually sees), fall back to the registry's compiled/original.
            pragma = (
                _extract_pragma_from_source(source_code)
                or compiled
                or v_entry.get("pragma", "")
                or "unknown"
            )
            record = {
                "id": _derive_id(rel_path),
                "category": category,
                "name": sol_path.name,
                "path": rel_path,
                "pragma": pragma,
                "vulnerabilities": list(v_entry.get("vulnerabilities", [])),
                "loc": source_code.count("\n") + (0 if source_code.endswith("\n") else 1),
                "source_code": source_code,
            }
            contracts.append(record)
            per_cat[category] += 1

    return {
        "dataset": "smartbugs-curated",
        "source_repo": SOURCE_REPO_URL,
        "categories": list(TARGET_CATEGORIES),
        "total_contracts": len(contracts),
        "count_per_category": per_cat,
        "contracts": contracts,
    }


def main() -> None:
    out = build()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=2))
    summary = (
        f"Wrote {OUT_PATH.relative_to(ROOT)} — "
        f"{out['total_contracts']} contracts ("
        + ", ".join(f"{cat}={n}" for cat, n in out["count_per_category"].items())
        + ")"
    )
    print(summary)


if __name__ == "__main__":
    main()
