"""Validate that a DeFiHackLabs candidate is expressible as a flat-ABI FuzzInput.

Given a target ABI + fork pin + a hand-authored exploit FuzzInput, this
scaffolds a minimal fork project, renders fork.sol.tpl via FoundryFuzzer, runs
`forge test`, and reports whether a BUG_SIGNAL line
appears. This is the empirical gate for promoting a contract from
manifest(skip) → enrich(runnable) under the target-only fork harness.

Usage:
    uv run python utils/validate_fork_candidate.py <spec.json>

spec.json:
{
  "id": "2022-10_BEGO",
  "chain": "bsc", "block": 21855314,
  "target_address": "0x…", "contract_name": "BEGO",
  "abi_path": "data/defihacklabs/source/2022-10_BEGO/abi.json",
  "calls": [["mint", […], "0x0", "attacker_address"], …]
}
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src" / "experiment" / "run"))

from fuzz.config import ForkConfig
from fuzz.fuzzer.foundry import FoundryFuzzer
from scaffold import RPC_ENDPOINTS, resolved_endpoints, _ensure_forge_std  # noqa: E402


class _FI:
    def __init__(self, calls, desc=""):
        self.calls = calls
        self.description = desc


def _write_toml(work: Path) -> None:
    lines = [
        "[profile.default]", 'src = "src"', 'out = "out"', 'libs = ["lib"]',
        "auto_detect_solc = true", "", "[rpc_endpoints]",
    ]
    # RPC_ENDPOINTS is chain→[urls]; write the best (first) endpoint per chain.
    lines += [f'{c} = "{resolved_endpoints(c)[0]}"' for c in RPC_ENDPOINTS]
    (work / "foundry.toml").write_text("\n".join(lines) + "\n")


def validate(spec: dict) -> tuple[bool, str]:
    abi = json.loads((ROOT / spec["abi_path"]).read_text())
    if isinstance(abi, dict):
        abi = abi.get("abi", abi)
    fork = ForkConfig(
        chain=spec["chain"],
        fork_block=spec["block"],
        target_address=spec["target_address"].lower(),
    )
    # Load the verified source when the spec points to it, so validation matches a
    # real run — which always passes --source. Absent → ABI-only.
    contract_source = None
    if spec.get("source_path"):
        sp = ROOT / spec["source_path"]
        if sp.is_file():
            contract_source = sp.read_text()
    fuzzer = FoundryFuzzer(
        "/tmp", spec["contract_name"], abi=abi, fork=fork,
        contract_source=contract_source,
        external=spec.get("external"),
        setup_template=spec.get("setup_template"),
    )
    test_src = fuzzer._build_test(_FI(spec["calls"], spec.get("id", "")))

    # Sanitize the id for the temp-dir prefix: a dataset id like
    # "defihacklabs/2022-10_BEGO" contains a "/", which mkdtemp treats as a path
    # separator and fails on (the parent dir doesn't exist).
    _slug = str(spec.get("id", "x")).replace("/", "_")
    work = Path(tempfile.mkdtemp(prefix=f"forkval_{_slug}_"))
    (work / "src").mkdir()
    (work / "test").mkdir()
    _write_toml(work)
    _ensure_forge_std(work)
    # The generated fork test `import "./Harness.sol"` — write it next to the test.
    from fuzz.fuzzer.foundry import _write_harness_file
    _write_harness_file(work / "test")
    (work / "test" / "__sc_fuzz__.t.sol").write_text(test_src)

    proc = subprocess.run(
        ["forge", "test", "--match-test", "test_fuzz_input", "-vv"],
        cwd=work, capture_output=True, text=True, timeout=600,
    )
    out = proc.stdout + "\n" + proc.stderr
    signals = [ln.strip() for ln in out.splitlines() if "BUG_SIGNAL" in ln]
    ok = bool(signals)
    print(f"\n=== {spec.get('id')} === work={work}")
    print(f"forge rc={proc.returncode}  signals={signals}")
    if not ok:
        # surface the tail for debugging (revert reasons / compile errors)
        print("\n".join(out.splitlines()[-40:]))
    return ok, "\n".join(signals)


if __name__ == "__main__":
    spec = json.loads(Path(sys.argv[1]).read_text())
    ok, _ = validate(spec)
    sys.exit(0 if ok else 1)
