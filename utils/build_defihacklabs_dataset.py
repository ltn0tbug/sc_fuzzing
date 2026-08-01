"""Build the legacy DeFiHackLabs intermediate JSON from fetched source metadata.

Reads:
  - legacy_intermediate/curated_targets.json  (one entry per curated PoC: id, chain, block, target)
  - dataset/defihacklabs/source/<safe_id>/meta.json   (fetched verified-source metadata)

Writes (gitignored staging — inputs to restructure_datasets.py):
  - legacy_intermediate/defihacklabs.json          full dataset (skip flags set)
  - legacy_intermediate/defihacklabs-usable.json   subset where skip=False
"""
from __future__ import annotations
import json
from pathlib import Path
from collections import Counter

# NOTE: emits the LEGACY per-dataset schema into legacy_intermediate/. After
# (re)building, run `utils/restructure_datasets.py` to convert these
# into the canonical raw/manifest/enrich files under ./data/.
REPO      = Path(__file__).resolve().parents[1]                  # repo root
DS_DIR    = REPO / "data"
DHL       = DS_DIR / "defihacklabs"                              # canonical source/ tree
LEGACY    = REPO / "utils" / "legacy_intermediate"  # gitignored staging
DATASET   = LEGACY / "defihacklabs.json"
USABLE    = LEGACY / "defihacklabs-usable.json"
CURATED   = LEGACY / "curated_targets.json"
SRC_DIR   = DHL / "source"
OVERRIDES = LEGACY / "skip_overrides.json"   # post-fetch skip reasons (durable)


def build_entry(target: dict, meta: dict) -> dict:
    """Compose a dataset entry from a curated_target row + fetched meta."""
    safe_id = target["id"].replace("/", "_")
    out = {
        "id":              f"defihacklabs/{target['id']}",
        "dataset_kind":    "defihacklabs",
        "poc_path":        f"ref/DeFiHackLabs/src/test/{target['poc_path']}",
        "chain":           target["chain"],
        "fork_block":      target["fork_block"],
        "target_address":  target["target_address"],
        "target_contract": meta.get("contract_name"),
        "compiler_version": meta.get("compiler_version"),
        "optimizer":       meta.get("optimizer", False),
        "optimizer_runs":  meta.get("optimizer_runs", 200),
        "evm_version":     meta.get("evm_version", "default"),
        "license":         meta.get("license", ""),
        "proxy":           meta.get("proxy", False),
        "implementation":  meta.get("implementation"),
        "source_dir":      f"data/defihacklabs/source/{safe_id}",
        "source_files":    meta.get("source_files", []),
        "primary_source":  meta.get("primary_source"),
        "multifile":       meta.get("multifile", False),
        "abi_path":        (f"data/defihacklabs/source/{safe_id}/"
                            f"{meta['abi_path']}") if meta.get("abi_path") else None,
        "verified":        bool(meta.get("verified")),
        "skip":            not bool(meta.get("verified")),
        "skip_reason":     meta.get("skip_reason"),
    }
    return out


def main() -> int:
    targets = json.loads(CURATED.read_text())
    # Post-fetch overrides: entries that pass Etherscan verification but fail
    # at scaffold / harness time. Keyed by curated id ("YYYY-MM_Name").
    overrides: dict[str, str] = {}
    if OVERRIDES.exists():
        ov = json.loads(OVERRIDES.read_text())
        overrides = ov.get("skips", {})
    entries = []
    for t in targets:
        safe_id = t["id"].replace("/", "_")
        meta_path = SRC_DIR / safe_id / "meta.json"
        if not meta_path.exists():
            entries.append({
                "id": f"defihacklabs/{t['id']}",
                "dataset_kind": "defihacklabs",
                "skip": True,
                "skip_reason": "no_metadata",
                "chain": t["chain"],
                "fork_block": t["fork_block"],
                "target_address": t["target_address"],
            })
            continue
        meta = json.loads(meta_path.read_text())
        entry = build_entry(t, meta)
        # Apply harness-side skip override if present
        if t["id"] in overrides and not entry.get("skip"):
            entry["skip"] = True
            entry["skip_reason"] = overrides[t["id"]]
        entries.append(entry)

    skip_reasons = Counter(
        e.get("skip_reason") or "ok" for e in entries
    )

    dataset = {
        "source_repo":     "https://github.com/SunWeb3Sec/DeFiHackLabs",
        "dataset":         "defihacklabs",
        "description":     "Curated subset of DeFiHackLabs PoCs targeting single-contract bugs reproducible on chain forks. Sources fetched from Etherscan/BscScan via the v2 unified API.",
        "total_contracts": len(entries),
        "verified":        sum(1 for e in entries if not e.get("skip")),
        "skip_count":      sum(1 for e in entries if e.get("skip")),
        "skip_reasons":    dict(skip_reasons),
        "chains":          dict(Counter(e["chain"] for e in entries if "chain" in e)),
        "contracts":       entries,
    }
    DATASET.parent.mkdir(parents=True, exist_ok=True)
    DATASET.write_text(json.dumps(dataset, indent=2))

    usable_entries = [e for e in entries if not e.get("skip")]
    usable = dict(dataset)
    usable["dataset"] = "defihacklabs-usable"
    usable["description"] = "Experiment-ready DeFiHackLabs subset (skip=False)."
    usable["total_contracts"] = len(usable_entries)
    usable["contracts"] = usable_entries
    USABLE.write_text(json.dumps(usable, indent=2))

    print(f"wrote {DATASET.name}: {dataset['verified']}/{dataset['total_contracts']} verified")
    print(f"wrote {USABLE.name}:  {usable['total_contracts']} usable")
    print(f"skip reasons: {dict(skip_reasons)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
