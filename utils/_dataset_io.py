"""Flat working-doc bridge for the PoC validators.

The validators (`validate_pocs`, `validate_defihacklabs_pocs`,
`validate_defihacklabs_bugsignal`) were written against the old single
`*-usable.json` flat shape — one dict per contract carrying
`skip`/`skip_reason`/`category`/`poc`/`source`/`fork`/`provenance`. The dataset now
stores those across three NORMALIZED files (`raw.json` / `manifest.json` /
`enrich.json`) where each fact lives in exactly one layer (raw = facts, manifest =
curation, enrich = runnable payload only).

`load_working(key)` reconstructs the old flat list (raw ⋈ manifest ⋈ enrich),
re-deriving the fields stripped from manifest/enrich so a validator can keep
mutating `rec["skip"] / rec["poc"]` exactly as before; `save_working(key, doc)`
re-splits it back into the NORMALIZED manifest + enrich (no duplicated facts; raw is
the immutable input layer). Source paths stay dataset-folder-relative throughout —
same as on disk — so a round-trip is byte-stable. Keys: `"smartbugs"` | `"defihacklabs"`.
"""
from __future__ import annotations

import json
from pathlib import Path

DS_DIR = Path(__file__).resolve().parents[1] / "data"   # repo-root ./utils → ./data (dataset artifact)
_FOLDER = {"smartbugs": "smartbugs_curated", "defihacklabs": "defihacklabs"}
GENERATED_BY = "utils/restructure_datasets.py (+ validators via _dataset_io)"

# Inline-target runtime-deploy config stored in enrich.extend. These must survive
# the manifest⋈enrich round-trip (carried via provenance in load_working /
# re-emitted by _enrich_entry) — otherwise save_working silently drops them.
_RUNTIME_EXTEND_KEYS = ("constructor_args", "constructor_value", "pre_deploy", "setup_calls")

# Fork-target runtime config stored in enrich.extend (declared non-target callable
# contracts + per-sample full template). These must ALSO survive the round-trip:
# _enrich_entry's fork branch builds extend from a fixed field list, so without
# carrying these explicitly save_working silently drops a fork row's external/
# setup_template (this is how PLN's WETH/ROUTER declaration was lost once).
_FORK_EXTEND_KEYS = ("external", "setup_template")

# Carried from enrich.extend into the working-doc provenance and re-emitted by
# _enrich_entry, so a working-doc round-trip is lossless for both kinds.
_CARRIED_EXTEND_KEYS = _RUNTIME_EXTEND_KEYS + _FORK_EXTEND_KEYS


def _path(key: str, schema: str) -> Path:
    # Normalized layout: <folder>/{raw,manifest,enrich}.json (no redundant prefix).
    return DS_DIR / _FOLDER[key] / f"{schema}.json"


def _write_json(path: Path, doc: dict) -> None:
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def load_working(key: str) -> dict:
    """raw ⋈ manifest ⋈ enrich → the old flat `{dataset, kind, contracts:[...]}`."""
    raw = json.loads(_path(key, "raw").read_text())
    man = {m["id"]: m for m in json.loads(_path(key, "manifest").read_text())["contracts"]}
    enr = {c["id"]: c for c in json.loads(_path(key, "enrich").read_text())["contracts"]}
    kind = raw["kind"]
    contracts = []
    for rc in raw["contracts"]:
        m = man.get(rc["id"], {})
        e = enr.get(rc["id"])
        # raw facts + manifest validation merged (so reference_exploit is visible).
        prov = {**(rc.get("provenance") or {}), **(m.get("validation") or {})}
        # Carry inline-target runtime-deploy config from enrich.extend so it
        # survives the round-trip (raw/manifest don't store it). Without this,
        # save_working would silently drop constructor_args / pre_deploy / etc.
        category = m.get("category") or rc.get("category")   # category lives in raw now
        poc = None
        if e:
            _ext = e.get("extend") or {}
            for _k in _CARRIED_EXTEND_KEYS:
                if _ext.get(_k) is not None:
                    prov[_k] = _ext[_k]
            poc = e.get("poc")
            if poc is not None and kind == "fork":
                # poc.category is derived from raw (stripped from enrich on disk) —
                # re-add it so the flat working doc matches the pre-normalization shape.
                poc = {**poc, "category": category}
        contracts.append({
            "id": rc["id"],
            "kind": kind,
            "category": category,
            "target_contract": rc.get("target_contract"),
            "compiler": rc.get("compiler"),
            "skip": bool(m.get("skip", True)),
            "skip_reason": m.get("skip_reason"),
            "source": rc.get("source") or {},
            "fork": rc.get("fork"),
            "provenance": prov,
            "poc": poc,
        })
    return {"dataset": raw["dataset"], "kind": kind, "contracts": contracts}


def _manifest_entry(rec: dict) -> dict:
    prov = rec.get("provenance") or {}
    if rec["kind"] == "fork":
        validation = {
            "reference_exploit": prov.get("reference_exploit"),
            "fuzzer_bug_signal": bool(rec.get("poc")),
        }
    else:
        validation = {"poc_validated": bool(rec.get("poc"))}
    return {
        "id": rec["id"],
        "skip": bool(rec["skip"]),
        "skip_reason": rec.get("skip_reason") or None,
        "validation": validation,
    }


def _enrich_entry(rec: dict) -> dict:
    """Normalized enrich row: ONLY {id, poc, extend} with runtime-only extend keys.
    Facts (kind/category/compiler/source/fork/optimizer/evm/reference_exploit) and the
    derivable extend fields live in raw/manifest and are re-joined by the loader."""
    prov = rec.get("provenance") or {}
    # Only the runtime-only keys belong in enrich.extend (the loader re-derives the rest).
    carried = _FORK_EXTEND_KEYS if rec["kind"] == "fork" else _RUNTIME_EXTEND_KEYS
    extend = {k: prov[k] for k in carried if prov.get(k) is not None}
    poc = rec.get("poc")
    if poc is not None and rec["kind"] == "fork":
        poc = {k: v for k, v in poc.items() if k != "category"}   # derived from raw
    return {
        "id": rec["id"],
        "poc": poc,
        "extend": extend,
    }


def save_working(key: str, doc: dict) -> tuple[Path, Path]:
    """Re-split the flat doc into manifest + enrich (raw untouched). Returns paths."""
    recs = doc["contracts"]
    manifest = [_manifest_entry(r) for r in recs]
    enrich = [_enrich_entry(r) for r in recs if not r["skip"]]

    man_path, enr_path = _path(key, "manifest"), _path(key, "enrich")
    man_doc = json.loads(man_path.read_text())
    enr_doc = json.loads(enr_path.read_text())
    man_doc.update({"total_contracts": len(manifest), "contracts": manifest,
                    "generated_by": GENERATED_BY})
    man_doc["meta"] = {**man_doc.get("meta", {}),
                       "usable": sum(1 for m in manifest if not m["skip"]),
                       "skipped": sum(1 for m in manifest if m["skip"])}
    enr_doc.update({"total_contracts": len(enrich), "contracts": enrich,
                    "generated_by": GENERATED_BY})
    _write_json(man_path, man_doc)
    _write_json(enr_path, enr_doc)
    return man_path, enr_path
