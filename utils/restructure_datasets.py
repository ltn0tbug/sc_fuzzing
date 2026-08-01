#!/usr/bin/env python3
"""One-shot: rewrite both experiment datasets into the symmetric three-file layout.

For each dataset we emit, under `data/<dataset>/`:

    source/                         every contract's Solidity (single source of truth)
    raw.json                        raw scraped facts + source pointers (ALL contracts)
    manifest.json                   curation: skip / skip_reason / validation (ALL)
    enrich.json                     normalized runnable form {id, poc, extend} (skip=false only)

The three layers are NORMALIZED: each fact lives in exactly one file (raw = facts,
manifest = curation, enrich = runnable payload). The loader (schema.py) re-joins them
by id and reconstitutes the full per-contract record. Runtime-only setup lives in each
enrich contract's `extend` block. See `src/experiment/dataloader/schemas/` for the shape.

Inputs are the *previous* on-disk files (no network):
    smartbugs-curated.json          full 116, inline source_code   -> raw + source/
    smartbugs-curated-usable.json   75, refined skip + authored poc -> manifest + enrich
    defihacklabs.json               full 42, fork facts            -> raw
    defihacklabs-usable.json        32, validated skip + poc       -> manifest + enrich
    defihacklabs/sources/<id>/      multifile source trees         -> moved to source/<id>/
    defihacklabs/curated_targets.json  target-address provenance   -> raw.provenance

Idempotent: rerunning regenerates the files and source/ from the same inputs.

    uv run python utils/restructure_datasets.py [--check]
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

UTILS_DIR = Path(__file__).resolve().parent
DS_DIR = UTILS_DIR.parent / "data"   # repo-root ./utils → ./data (dataset artifact)

# Legacy inputs: the pre-refactor JSONs, relocated to a gitignored staging dir.
# This is the one-shot MIGRATION source; steady-state maintenance is done by the
# builders (raw) + validators (manifest/enrich), not by re-running this script.
LEGACY = UTILS_DIR / "legacy_intermediate"
SB_RAW_IN = LEGACY / "smartbugs-curated.json"
SB_USABLE_IN = LEGACY / "smartbugs-curated-usable.json"
DH_RAW_IN = LEGACY / "defihacklabs.json"
DH_USABLE_IN = LEGACY / "defihacklabs-usable.json"
DH_TARGETS_IN = LEGACY / "curated_targets.json"
DH_SOURCES_OLD = DS_DIR / "defihacklabs" / "sources"

# Output dataset folders.
SB_DIR = DS_DIR / "smartbugs_curated"
DH_DIR = DS_DIR / "defihacklabs"

GENERATED_BY = "utils/restructure_datasets.py"


def _write_json(path: Path, doc: dict) -> None:
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def _envelope(dataset: str, kind: str, schema: str, src_repo: str, desc: str,
              contracts: list, meta: dict) -> dict:
    return {
        "dataset": dataset,
        "kind": kind,
        "schema": schema,
        "source_repo": src_repo,
        "description": desc,
        "generated_by": GENERATED_BY,
        "total_contracts": len(contracts),
        "meta": meta,
        "contracts": contracts,
    }


# ── SmartBugs Curated (inline) ────────────────────────────────────────────────

def build_smartbugs() -> None:
    raw_in = json.loads(SB_RAW_IN.read_text())
    usable_in = {c["id"]: c for c in json.loads(SB_USABLE_IN.read_text())["contracts"]}
    src_repo = raw_in["source_repo"]

    source_root = SB_DIR / "source"
    if source_root.exists():
        shutil.rmtree(source_root)

    raw_contracts, manifest_contracts, enrich_contracts = [], [], []

    for rc in raw_in["contracts"]:
        cid = rc["id"]                       # "<category>/<addr>"
        rel = f"source/{cid}.sol"            # dataset-folder-relative
        # 1) materialize source file
        dst = SB_DIR / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(rc["source_code"])

        uc = usable_in.get(cid)

        # 2) raw record (facts + source pointer; no inline blob)
        raw_contracts.append({
            "id": cid,
            "category": rc.get("category"),
            "target_contract": rc.get("target_contract"),
            "compiler": rc.get("pragma"),
            "source": {"path": rel},
            "provenance": {
                "name": rc.get("name"),
                "ref_path": rc.get("path"),          # original smartbugs-curated repo path
                "vulnerabilities": rc.get("vulnerabilities", []),
                "loc": rc.get("loc"),
            },
        })

        # 3) manifest record (curation layer; usable wins where present)
        if uc is not None:
            skip = bool(uc["skip"])
            skip_reason = uc.get("skip_reason") or None
            category = uc.get("category") or rc.get("category")
        else:
            skip = bool(rc.get("skip", True))
            skip_reason = (rc.get("skip_reason") or None)
            category = rc.get("category")
        # manifest is NORMALIZED: curation only (category/target_contract live in raw).
        manifest_contracts.append({
            "id": cid,
            "skip": skip,
            "skip_reason": skip_reason,
            "validation": {"poc_validated": bool(uc and uc.get("poc"))},
        })

        # 4) enrich record (runnable only) — NORMALIZED to {id, poc, extend}; facts
        #    (category/compiler/source) and vulnerabilities/loc are joined from raw.
        if uc is not None and not uc["skip"]:
            enrich_contracts.append({
                "id": cid,
                "poc": uc.get("poc"),
                "extend": {},   # inline runtime-only keys (ctor/pre_deploy) added by validators
            })

    meta = {"categories": raw_in.get("categories")
            or usable_in and json.loads(SB_USABLE_IN.read_text()).get("meta", {}).get("categories")}
    _write_json(SB_DIR / "raw.json",
                _envelope("smartbugs_curated", "inline", "raw", src_repo,
                          "Full SmartBugs Curated set (4 DASP categories); source under source/.",
                          raw_contracts, {"categories": meta["categories"]}))
    _write_json(SB_DIR / "manifest.json",
                _envelope("smartbugs_curated", "inline", "manifest", src_repo,
                          "Curation layer over the raw set: skip/skip_reason per contract (joined to raw by id).",
                          manifest_contracts,
                          {"usable": sum(1 for m in manifest_contracts if not m["skip"]),
                           "skipped": sum(1 for m in manifest_contracts if m["skip"])}))
    _write_json(SB_DIR / "enrich.json",
                _envelope("smartbugs_curated", "inline", "enrich", src_repo,
                          "Runnable SmartBugs subset (skip=false), each with an authored+verified poc.",
                          enrich_contracts, {"categories": meta["categories"]}))
    print(f"smartbugs_curated: raw={len(raw_contracts)} manifest={len(manifest_contracts)} "
          f"enrich={len(enrich_contracts)} source-files={len(raw_contracts)}")


# ── DeFiHackLabs (fork) ───────────────────────────────────────────────────────

def _dh_targets_provenance() -> dict[str, dict]:
    if not DH_TARGETS_IN.exists():
        return {}
    out = {}
    for t in json.loads(DH_TARGETS_IN.read_text()):
        out[t["id"]] = {"target_address_source": t.get("target_address_source")}
    return out


def build_defihacklabs() -> None:
    raw_in = json.loads(DH_RAW_IN.read_text())
    usable_doc = json.loads(DH_USABLE_IN.read_text())
    usable_in = {c["id"]: c for c in usable_doc["contracts"]}
    src_repo = raw_in["source_repo"]
    targets = _dh_targets_provenance()

    # Move sources/<id>/ -> source/<id>/ (verbatim trees; gitignored either way).
    source_root = DH_DIR / "source"
    if DH_SOURCES_OLD.exists() and not source_root.exists():
        shutil.move(str(DH_SOURCES_OLD), str(source_root))
    elif DH_SOURCES_OLD.exists() and source_root.exists():
        for d in DH_SOURCES_OLD.iterdir():
            shutil.move(str(d), str(source_root / d.name))
        shutil.rmtree(DH_SOURCES_OLD, ignore_errors=True)

    raw_contracts, manifest_contracts, enrich_contracts = [], [], []

    for rc in raw_in["contracts"]:
        cid = rc["id"]                       # "defihacklabs/<id>"
        short = cid.split("/")[-1]
        rel_dir = f"source/{short}"
        files = rc.get("source_files") or []
        primary = rc.get("primary_source") or (files[0] if files else None)
        multifile = bool(rc.get("multifile"))
        abi_rel = f"{rel_dir}/abi.json" if (source_root / short / "abi.json").exists() else None

        uc = usable_in.get(cid)

        # raw record
        raw_contracts.append({
            "id": cid,
            "category": (uc or {}).get("category"),
            "target_contract": rc.get("target_contract"),
            "compiler": rc.get("compiler_version"),
            "source": {
                "dir": rel_dir, "files": files, "primary": primary,
                "multifile": multifile, "abi_path": abi_rel,
            },
            "fork": {
                "chain": rc.get("chain"),
                "block": rc.get("fork_block"),
                "target_address": rc.get("target_address"),
            },
            "provenance": {
                "poc_path": rc.get("poc_path"),
                "optimizer": rc.get("optimizer"),
                "optimizer_runs": rc.get("optimizer_runs"),
                "evm_version": rc.get("evm_version"),
                "license": rc.get("license"),
                "proxy": rc.get("proxy"),
                "implementation": rc.get("implementation"),
                "verified": rc.get("verified"),
                **targets.get(short, {}),
            },
        })

        # manifest record (usable carries the validated skip + reference_exploit)
        if uc is not None:
            skip = bool(uc["skip"])
            skip_reason = uc.get("skip_reason") or None
            category = uc.get("category")
            ref = (uc.get("provenance") or {}).get("reference_exploit")
        else:
            skip = True
            skip_reason = rc.get("skip_reason") or "not in validated subset (unverified/proxy/legacy)"
            category = None
            ref = None
        # manifest is NORMALIZED: curation only (category/target_contract live in raw;
        # reference_exploit is the canonical home — enrich joins it back by id).
        manifest_contracts.append({
            "id": cid,
            "skip": skip,
            "skip_reason": skip_reason,
            "validation": {
                "reference_exploit": ref,
                "fuzzer_bug_signal": bool(uc and uc.get("poc")),
            },
        })

        # enrich record (runnable only) — NORMALIZED to {id, poc, extend}; facts
        # (category/compiler/source) + fork/optimizer/evm/reference_exploit are joined
        # back from raw/manifest by the loader, so only runtime-only keys live here.
        if uc is not None and not uc["skip"]:
            poc = uc.get("poc")
            if poc is not None:
                poc = {k: v for k, v in poc.items() if k != "category"}   # derived from raw
            enrich_contracts.append({
                "id": cid,
                "poc": poc,
                "extend": {},   # fork runtime-only keys (external/setup_template) added by validators
            })

    meta_raw = {k: raw_in.get(k) for k in ("chains", "verified", "skip_count")}
    _write_json(DH_DIR / "raw.json",
                _envelope("defihacklabs", "fork", "raw", src_repo,
                          "Full DeFiHackLabs candidate set (fork facts + multifile source under source/).",
                          raw_contracts, meta_raw))
    _write_json(DH_DIR / "manifest.json",
                _envelope("defihacklabs", "fork", "manifest", src_repo,
                          "Curation layer: skip/skip_reason + reference-exploit & bug-signal validation (joined to raw by id).",
                          manifest_contracts,
                          {"usable": sum(1 for m in manifest_contracts if not m["skip"]),
                           "skipped": sum(1 for m in manifest_contracts if m["skip"]),
                           "reference_exploits_reproduced":
                               sum(1 for m in manifest_contracts
                                   if (m["validation"].get("reference_exploit") or {}).get("reproduced"))}))
    _write_json(DH_DIR / "enrich.json",
                _envelope("defihacklabs", "fork", "enrich", src_repo,
                          "Runnable DeFiHackLabs subset (skip=false): {id, poc, extend}; facts joined from raw.",
                          enrich_contracts, {"chains": raw_in.get("chains")}))
    print(f"defihacklabs: raw={len(raw_contracts)} manifest={len(manifest_contracts)} "
          f"enrich={len(enrich_contracts)} source-dirs={len(list(source_root.iterdir())) if source_root.exists() else 0}")


def _check() -> None:
    """Sanity-check the emitted files load + counts line up."""
    import sys
    sys.path.insert(0, str(UTILS_DIR.parent / "src" / "experiment" / "dataloader"))
    import importlib
    schema = importlib.import_module("schema")
    importlib.reload(schema)
    for key, exp_kind in (("smartbugs", "inline"), ("defihacklabs", "fork")):
        ds = schema.load_dataset(key)
        allc = schema.load_all(key)
        assert ds.kind == exp_kind, (key, ds.kind)
        assert all(not c.skip for c in ds.contracts), f"{key}: enrich has skipped contract"
        print(f"  {key}: enrich={len(ds.contracts)} all={len(allc)} kind={ds.kind} OK")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="load the emitted files and assert invariants")
    args = ap.parse_args()
    SB_DIR.mkdir(parents=True, exist_ok=True)
    DH_DIR.mkdir(parents=True, exist_ok=True)
    build_smartbugs()
    build_defihacklabs()
    if args.check:
        _check()


if __name__ == "__main__":
    main()
