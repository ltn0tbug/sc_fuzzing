"""Unified dataset loader for the normalized three-layer layout.

This loader is *code* (src/experiment/dataloader/); the dataset *data* lives in
repo-root `./data/`. Each dataset has its own folder under `data/`:

    <dataset>/
      source/                       every contract's Solidity (single source of truth)
      raw.json                      facts + source pointers + provenance (ALL contracts)
      manifest.json                 curation: skip / skip_reason / validation (ALL contracts)
      enrich.json                   runnable payload {id, poc, extend} (skip=false only)

NORMALIZED: each fact lives in exactly ONE layer — no cross-file duplication, so a row
is edited in one place. raw owns the facts (category/target_contract/compiler/source/
fork/provenance); manifest owns curation (skip/skip_reason/validation incl. the
canonical reference_exploit); enrich owns ONLY the runnable payload (poc + runtime-only
`extend` keys: external/setup_template | constructor_args/pre_deploy/setup_calls). The
loader re-joins the layers by id and reconstitutes the full per-contract record
(`extend`/`poc` include the derived fields), so Contract records are identical to the
pre-normalization layout and downstream run/eda code is untouched.

All three files share one envelope:

    { "dataset": "...", "kind": "inline"|"fork", "schema": "raw"|"manifest"|"enrich",
      "source_repo": ..., "description": ..., "generated_by": ...,
      "total_contracts": N, "meta": {...}, "contracts": [ ... ] }

Source paths inside the JSON are **dataset-folder-relative** (e.g. `source/<id>.sol`);
the loader rewrites them to **repo-relative** strings so callers can do
`ROOT / contract.source.dir` unchanged. `./ref` is never read here.

Public API:
    load_dataset(name)  -> Dataset    # ENRICH⋈RAW⋈MANIFEST: runnable records (run/ consumes)
    load_all(name)      -> [Contract] # RAW⋈MANIFEST⋈ENRICH: every contract (eda/ consumes)
    load_manifest(name) -> [dict]     # curation rows verbatim
    load_raw(name)      -> dict        # raw envelope verbatim

`name` is the short key `"smartbugs"` | `"defihacklabs"` (kept stable so the run
registry's `json_key` does not change).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# Loader code lives in src/experiment/dataloader/; dataset data lives in repo-root
# ./data/. Decoupled on purpose: src/ is code only, data/ is the generated artifact.
_HERE = Path(__file__).resolve().parent                # src/experiment/dataloader/
ROOT = _HERE.parents[2]                                # repo root
DATA_DIR = ROOT / "data"                               # ./data/
_REPO_REL = DATA_DIR.relative_to(ROOT)                 # data

# Short key → dataset folder (the folder already names the dataset, so layer
# files carry no redundant prefix: <folder>/{raw,manifest,enrich}.json).
_DATASETS = {
    "smartbugs": "smartbugs_curated",
    "defihacklabs": "defihacklabs",
}


def _folder(name: str) -> Path:
    if name not in _DATASETS:
        raise ValueError(f"unknown dataset {name!r}; expected one of {list(_DATASETS)}")
    return DATA_DIR / _DATASETS[name]


def _file(name: str, schema: str) -> Path:
    return _folder(name) / f"{schema}.json"


def _repo_rel(name: str, rel: str | None) -> str | None:
    """Dataset-folder-relative path → repo-relative string (for `ROOT / ...`)."""
    if not rel:
        return rel
    return str(_REPO_REL / _DATASETS[name] / rel)


# ── Typed records ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ForkInfo:
    chain: str
    block: int
    target_address: str


@dataclass(frozen=True)
class SourceInfo:
    inline: str | None = None      # always None now (source lives on disk under source/)
    path: str | None = None        # repo-relative single .sol (inline kind)
    dir: str | None = None         # repo-relative source tree (fork kind)
    files: list[str] | None = None
    primary: str | None = None
    multifile: bool | None = None
    abi_path: str | None = None    # repo-relative ABI json (fork kind)


@dataclass(frozen=True)
class Contract:
    id: str
    kind: str                      # "inline" | "fork"
    target_contract: str | None = None
    category: str | None = None
    compiler: str | None = None    # pragma (inline) or solc version string (fork)
    skip: bool = False
    skip_reason: str | None = None
    source: SourceInfo = field(default_factory=SourceInfo)
    fork: ForkInfo | None = None
    extend: dict = field(default_factory=dict)     # dataset-specific runtime setup (enrich)
    provenance: dict = field(default_factory=dict) # raw facts (load_all only)
    poc: dict | None = None        # verified proof-of-concept (None when skipped)

    @property
    def is_fork(self) -> bool:
        return self.kind == "fork"

    @property
    def is_inline(self) -> bool:
        return self.kind == "inline"

    @property
    def safe_id(self) -> str:
        """Filesystem-safe id used for scaffold dirs + result filenames."""
        return self.id.replace("/", "_")


@dataclass(frozen=True)
class Dataset:
    name: str          # "smartbugs_curated" | "defihacklabs"
    kind: str          # "inline" | "fork"
    contracts: list[Contract]
    meta: dict = field(default_factory=dict)


# ── Parsing ───────────────────────────────────────────────────────────────────

def _fork_from(d: dict | None) -> ForkInfo | None:
    if not d or d.get("target_address") is None:
        return None
    return ForkInfo(chain=d["chain"], block=d["block"], target_address=d["target_address"])


def _source(name: str, src: dict) -> SourceInfo:
    return SourceInfo(
        inline=None,
        path=_repo_rel(name, src.get("path")),
        dir=_repo_rel(name, src.get("dir")),
        files=src.get("files"),
        primary=src.get("primary"),
        multifile=src.get("multifile"),
        abi_path=_repo_rel(name, src.get("abi_path")),
    )


# The three layers are NORMALIZED: each fact lives in exactly one file.
#   raw      — facts (category/target_contract/compiler/source/fork/provenance), ALL rows
#   manifest — curation (skip/skip_reason/validation incl. reference_exploit), ALL rows
#   enrich   — runnable payload only (poc + the runtime-only extend keys), skip=false rows
# The loader re-joins them by id and reconstitutes the full `extend`/`poc` dicts (the
# duplicated fields removed from disk are derived back here), so Contract records are
# identical to the pre-normalization layout — downstream run/eda code is untouched.

def _build_poc(kind: str, raw_category: str | None, poc: dict | None) -> dict | None:
    if poc is None:
        return None
    poc = dict(poc)
    if kind == "fork":
        poc["category"] = raw_category   # == raw.category (dropped from enrich on disk)
    return poc


def _build_extend(kind: str, raw_row: dict, man_row: dict, enrich_extend: dict | None) -> dict:
    """Reconstitute the runtime `extend` bag from raw facts + manifest curation +
    the enrich-only payload (external/setup_template | ctor/pre_deploy/setup_calls)."""
    prov = raw_row.get("provenance") or {}
    if kind == "fork":
        fk = raw_row.get("fork") or {}
        ext = {
            "chain": fk.get("chain"),
            "block": fk.get("block"),
            "target_address": fk.get("target_address"),
            "evm_version": prov.get("evm_version"),
            "optimizer": prov.get("optimizer"),
            "optimizer_runs": prov.get("optimizer_runs"),
            # Proxy metadata (coverage anchors on the IMPLEMENTATION's code + PCs
            # for an EIP-1967/Etherscan-detected proxy — the arena records the
            # delegatecall frame under the impl address, not the proxy target).
            "proxy": prov.get("proxy"),
            "implementation": prov.get("implementation"),
            "reference_exploit": (man_row.get("validation") or {}).get("reference_exploit"),
        }
    else:
        ext = {"vulnerabilities": prov.get("vulnerabilities"), "loc": prov.get("loc")}
    ext.update(enrich_extend or {})
    return ext


def _assemble(name: str, kind: str, raw_row: dict, man_row: dict,
              enrich_row: dict | None, with_provenance: bool) -> Contract:
    """Build one Contract by joining the (normalized) layers for a single id."""
    runnable = enrich_row is not None
    return Contract(
        id=raw_row["id"],
        kind=kind,
        target_contract=raw_row.get("target_contract"),
        category=raw_row.get("category"),
        compiler=raw_row.get("compiler"),
        skip=bool(man_row.get("skip", True)) if not runnable else False,
        skip_reason=man_row.get("skip_reason") if not runnable else None,
        source=_source(name, raw_row.get("source") or {}),
        fork=_fork_from(raw_row.get("fork")),
        extend=_build_extend(kind, raw_row, man_row, enrich_row.get("extend")) if runnable else {},
        provenance=(raw_row.get("provenance") or {}) if with_provenance else {},
        poc=_build_poc(kind, raw_row.get("category"), enrich_row.get("poc")) if runnable else None,
    )


def load_dataset(name: str) -> Dataset:
    """ENRICH ⋈ RAW ⋈ MANIFEST: runnable Contract records (skip=false), run-loop interface."""
    enr = json.loads(_file(name, "enrich").read_text())
    raw = load_raw(name)
    kind = raw["kind"]
    raw_idx = {c["id"]: c for c in raw["contracts"]}
    man_idx = {m["id"]: m for m in load_manifest(name)}
    contracts = [
        _assemble(name, kind, raw_idx[c["id"]], man_idx.get(c["id"], {}), c, with_provenance=False)
        for c in enr["contracts"]
    ]
    return Dataset(
        name=enr.get("dataset", name),
        kind=kind,
        contracts=contracts,
        meta=enr.get("meta", {}),
    )


def load_raw(name: str) -> dict:
    """RAW envelope verbatim (all contracts; facts + source pointers)."""
    return json.loads(_file(name, "raw").read_text())


def load_manifest(name: str) -> list[dict]:
    """MANIFEST curation rows verbatim (all contracts; skip / category / validation)."""
    return json.loads(_file(name, "manifest").read_text())["contracts"]


def load_all(name: str) -> list[Contract]:
    """RAW ⋈ MANIFEST ⋈ ENRICH → a Contract per contract (skipped included), for EDA.

    Facts (category/source/fork/provenance) come from raw; skip/skip_reason from the
    manifest; `poc` and the runtime `extend` are reconstituted from enrich (runnable ids).
    """
    raw = load_raw(name)
    man = {m["id"]: m for m in load_manifest(name)}
    enr = {c["id"]: c for c in json.loads(_file(name, "enrich").read_text())["contracts"]}
    kind = raw["kind"]
    return [
        _assemble(name, kind, rc, man.get(rc["id"], {}), enr.get(rc["id"]), with_provenance=True)
        for rc in raw["contracts"]
    ]


if __name__ == "__main__":
    for key in _DATASETS:
        ds = load_dataset(key)
        allc = load_all(key)
        n_skip = sum(1 for c in allc if c.skip)
        print(f"{key}: kind={ds.kind} enrich={len(ds.contracts)} all={len(allc)} skipped={n_skip}")
        if ds.contracts:
            c = ds.contracts[0]
            print(f"  runnable e.g. {c.id} target={c.target_contract} src={c.source.path or c.source.dir}")
