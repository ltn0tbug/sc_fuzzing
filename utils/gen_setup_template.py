"""Generate per-sample full fork setup templates from the canonical fork.sol.tpl.

The user's design choice is a "full file per sample": each DeFiHackLabs enrich
contract that declares `extend.external` (callable non-target contracts) gets its
OWN complete, self-contained Solidity test contract under its source/ dir, and the
fuzzer substitutes only the fuzz body (`${calls_code}`) into it. To keep the
financial-loss oracle from drifting across those copies, the per-sample file is
STAMPED from the single canonical base (`fuzzer/templates/fork.sol.tpl`): we bake
the external interface declarations + address constants into the base's
`${external_interfaces}` / `${external_consts}` holes (via FoundryFuzzer's own
`_render_external_decls`, so the rendering matches the runtime path exactly) and
leave every other placeholder for the fuzzer to fill at run time.

After generation, hand-editing a file to add a bespoke mock contract is fine —
re-running this script would overwrite it, so guard such files (or extend this
script). Target-only samples (empty `external`) get NO file; they use the built-in
fork.sol.tpl with the external holes rendered empty.

Usage:
    uv run python utils/gen_setup_template.py [<id-substring> ...]
    # no args → regenerate for every enrich sample with a non-empty `external`
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from string import Template

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fuzz.config import ForkConfig            # noqa: E402
from fuzz.fuzzer.foundry import FoundryFuzzer, _TEMPLATES_DIR  # noqa: E402

DATASET_DIR = ROOT / "data" / "defihacklabs"
ENRICH = DATASET_DIR / "enrich.json"
RAW = DATASET_DIR / "raw.json"   # facts (target_contract/source/fork) joined back in


def _gen_one(contract: dict) -> str | None:
    """Stamp out one per-sample full template; return the repo-relative path
    written, or None when the contract declares no external contracts."""
    external = (contract.get("extend") or {}).get("external") or []
    if not external:
        return None

    src_dir = (contract.get("source") or {}).get("dir")
    if not src_dir:
        raise SystemExit(f"{contract['id']}: missing source.dir")

    ext = contract["extend"]
    fork = ForkConfig(
        chain=ext.get("chain", "mainnet"),
        fork_block=ext.get("block", 0),
        target_address=str(ext.get("target_address", "0x0")).lower(),
    )
    # Only _render_external_decls is needed (it reads self._external) — the ABI is
    # irrelevant here, so pass an empty one.
    fuzzer = FoundryFuzzer("/tmp", contract["target_contract"], abi=[], fork=fork, external=external)
    ifaces, consts = fuzzer._render_external_decls()

    base = (_TEMPLATES_DIR / "fork.sol.tpl").read_text()
    # Partial substitution: fill ONLY the external holes, leaving ${calls_code} and
    # the fork constants (${target_address}/${chain}/… ${interface_decl}) for the
    # fuzzer to fill per run.
    baked = Template(base).safe_substitute(external_interfaces=ifaces, external_consts=consts)

    out_path = DATASET_DIR / src_dir / "setup.sol.tpl"
    out_path.write_text(baked)
    rel = out_path.relative_to(ROOT).as_posix()
    print(f"  {contract['id']} → {rel}")
    return rel


def main(argv: list[str]) -> int:
    # enrich is normalized to {id, poc, extend}; the generator also needs
    # target_contract/source/chain/block/target_address, which live in raw — join
    # them back (source paths stay dataset-folder-relative, as _gen_one expects).
    raw = {c["id"]: c for c in json.loads(RAW.read_text())["contracts"]}
    contracts = []
    for e in json.loads(ENRICH.read_text())["contracts"]:
        r = raw.get(e["id"], {})
        fk = r.get("fork") or {}
        ext = dict(e.get("extend") or {})
        ext.setdefault("chain", fk.get("chain"))
        ext.setdefault("block", fk.get("block"))
        ext.setdefault("target_address", fk.get("target_address"))
        contracts.append({
            "id": e["id"],
            "target_contract": r.get("target_contract"),
            "source": r.get("source") or {},
            "extend": ext,
        })
    selected = [
        c for c in contracts
        if not argv or any(s in c["id"] for s in argv)
    ]
    wrote = 0
    print(f"Generating setup templates ({len(selected)} candidate sample(s)):")
    for c in selected:
        if _gen_one(c) is not None:
            wrote += 1
    print(f"Done — {wrote} file(s) written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
