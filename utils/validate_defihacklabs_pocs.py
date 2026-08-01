#!/usr/bin/env python3
"""PoC-validate every DeFiHackLabs contract by running its reference exploit.

Unlike SmartBugs (where we *author* FuzzInput PoCs and run them through the
inline fund-flow harness), DeFiHackLabs ships a full foundry fork-exploit per
contract under `ref/DeFiHackLabs/src/test/<date>/<name>_exp.sol`. Those are
documented, on-chain-confirmed historical hacks. Here we *reference and re-run*
each one against its pinned fork block and record the empirical result:

  * `forge test` Success  -> exploit reproduces -> store a `poc` block.
  * fork/logic FAIL        -> record the reason, leave `poc: null`.

The fork state for all 32 blocks is already cached under
`~/.foundry/cache/rpc/<chain>/<block>` (populated by the experiment run), so
runs only make a couple of lightweight chainId/header calls and never re-fetch
state. We compile each exploit *in isolation* (one temp project per file) so a
version-sensitive file can't abort the others, with its own pragma-resolved
solc.

Vulnerability classes (`category`) use a DeFi-specific taxonomy authored in
`CATEGORIES` below (the dataset shipped them all as `null`).

Usage:
    uv run python utils/validate_defihacklabs_pocs.py            # run all
    uv run python utils/validate_defihacklabs_pocs.py --only <id>
    uv run python utils/validate_defihacklabs_pocs.py --write    # mutate JSON
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[1]
DHL = ROOT / "ref" / "DeFiHackLabs"
sys.path.insert(0, str(ROOT / "utils"))
from _dataset_io import load_working, save_working  # noqa: E402

# Layer-1 (reference replay) writes its result into manifest.validation.reference_exploit
# via the working-doc bridge; it never touches skip or the fuzzer `poc`.
DATASET_KEY = "defihacklabs"
SIDECAR = pathlib.Path("/tmp/dhl_validation.json")
WORK = pathlib.Path("/tmp/dhl_validate")

# Endpoints are only hit for fork-init metadata + any cache miss; state itself is
# already cached on disk. Ordered by reliability for deep-archive blocks.
ENDPOINTS = {
    "mainnet": [
        "https://eth.drpc.org",
        "https://1rpc.io/eth",
        "https://ethereum-rpc.publicnode.com",
    ],
    "bsc": [
        "https://bsc-mainnet.public.blastapi.io",
        "https://bsc.drpc.org",
        "https://api.tatum.io/v3/blockchain/node/bsc-mainnet",
    ],
}

# A reason string that means "try another endpoint" rather than "exploit failed".
_RPC_ERR = re.compile(
    r"historical state|createSelectFork|could not instantiate|error sending request"
    r"|missing trie|429|too many requests|timeout|connection|Unauthorized|521|-32000",
    re.I,
)

# ── DeFi-specific vulnerability taxonomy (per contract id suffix) ─────────────
# Authored from each exploit body + the linked root-cause analysis.
CATEGORIES: dict[str, str] = {
    "2020-12_Cover": "reward_accounting",        # Blacksmith.claimRewards mints excess COVER
    "2021-05_RariCapital": "reentrancy",         # cross-contract reentrancy in ibETH pool
    "2022-02_BuildF": "access_control",          # governance proposal executes arbitrary approve()
    "2022-06_InverseFinance": "price_oracle_manipulation",  # Curve LP spot-price oracle
    "2022-10_Templedao": "access_control",       # unprotected migrateStake(addr, amount)
    "2022-12_JAY": "reentrancy",                 # sell() reentered via receive()
    "2023-08_Uwerx": "unprotected_burn",         # transfer-to-pair burns, skim/sync inflate price
    "2024-09_PLN": "price_oracle_manipulation",  # flash-loan spot manipulation
    "2025-03_UNI": "price_oracle_manipulation",  # UniswapV2Pair reserve manipulation
    "2025-04_Roar": "price_oracle_manipulation", # UniswapV2Pair reserve manipulation
    "2022-10_ATK": "price_oracle_manipulation",  # flash-swap reserve manipulation (pancakeCall)
    "2022-10_BEGO": "arbitrary_mint",            # mint() with no access control
    "2022-12_DFS": "business_logic",             # token over-mints to pair, drained via skim() loop
    "2023-05_Bitpaidio": "reward_accounting",    # stake lock/withdraw reward miscalc
    "2023-05_FAPEN": "business_logic",           # wrong balance check in unstake()
    "2023-06_SELLC03": "price_oracle_manipulation",  # liquidity/miner reserve manipulation
    "2023-06_SHIDO": "reward_accounting",        # lock then immediate claim over-credits
    "2023-07_Bamboo": "price_oracle_manipulation",   # flash-loan price manipulation
    "2023-07_FFIST": "business_logic",           # airdrop-address transfer + sync reserve abuse
    "2024-09_WXETA": "arbitrary_mint",           # unprotected initialize() + mint()
    "2022-10_EFLeverVault": "price_oracle_manipulation",  # leveraged-vault price manipulation
    "2023-08_EHIVE": "reward_accounting",        # stake(0) + unstake chain duplicates reward
    "2023-10_WiseLending": "reentrancy",         # deposit/withdraw share-price reentrancy
    "2024-09_DOGGO": "business_logic",           # V3-flash token transfer-logic bug
    "2024-09_HANAToken": "business_logic",       # V3-flash token transfer-logic bug
    "2025-06_AAVEBoost": "reward_accounting",    # repeated boost-balance accrual
    "2022-08_EGD_Finance": "price_oracle_manipulation",  # flash-loan oracle (getEGDPrice)
    "2023-07_LUSD": "price_oracle_manipulation", # DODO flash-loan price manipulation
    "2023-10_MicDao": "business_logic",          # sybil helper-contract claim loop
    "2025-01_Ast": "business_logic",             # PancakeV3 flash-callback logic bug
    "2022-10_Uerii": "arbitrary_mint",           # public mint() missing access control
    "2023-05_BabyDogeCoin": "reentrancy",        # fee-on-transfer reentrancy
}


@dataclass
class Result:
    id: str
    chain: str
    block: int
    poc_path: str
    test_fn: str = ""
    passed: bool = False
    gas: int | None = None
    endpoint: str = ""
    reason: str = ""
    logs: list[str] = field(default_factory=list)


def _setup_project(exploit_rel: pathlib.Path, endpoint: str, chain: str) -> pathlib.Path:
    """Fresh isolated forge project containing just interface.sol + one exploit."""
    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "lib").mkdir(parents=True)
    (WORK / "src" / "test").mkdir(parents=True)
    os.symlink(DHL / "lib" / "forge-std", WORK / "lib" / "forge-std")
    shutil.copy(DHL / "src" / "test" / "interface.sol", WORK / "src" / "test" / "interface.sol")
    dst = WORK / "src" / "test" / exploit_rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(DHL / "src" / "test" / exploit_rel, dst)
    (WORK / "foundry.toml").write_text(
        "[profile.default]\n"
        "src='src'\nout='out'\nlibs=['lib']\n"
        'fs_permissions=[{access="read",path="./"}]\n'
        "evm_version='shanghai'\n"
        "[rpc_endpoints]\n"
        f'mainnet="{endpoint if chain == "mainnet" else ENDPOINTS["mainnet"][0]}"\n'
        f'bsc="{endpoint if chain == "bsc" else ENDPOINTS["bsc"][0]}"\n'
    )
    return WORK


def _run_forge(match_path: str) -> dict:
    p = subprocess.run(
        ["forge", "test", "--match-path", match_path, "-vv", "--json"],
        cwd=WORK, capture_output=True, text=True, timeout=600,
    )
    out = p.stdout.strip()
    if not out:
        return {"_err": p.stderr[-400:] or "no json output"}
    # forge --json may prepend solc lines (e.g. ">256 warnings") to stdout; the
    # result object is the last line that parses as JSON.
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {"_err": out[-400:]}


def run_one(c: dict) -> Result:
    poc_path = c["provenance"]["poc_path"]
    exploit_rel = pathlib.Path(poc_path).relative_to("ref/DeFiHackLabs/src/test")
    chain = c["fork"]["chain"]
    res = Result(id=c["id"], chain=chain, block=c["fork"]["block"], poc_path=poc_path)
    match_path = f"src/test/{exploit_rel}"

    last_reason = ""
    for endpoint in ENDPOINTS[chain]:
        _setup_project(exploit_rel, endpoint, chain)
        forged = _run_forge(match_path)
        if "_err" in forged:
            last_reason = forged["_err"]
            if _RPC_ERR.search(last_reason):
                continue            # endpoint problem -> try next
            res.reason = last_reason
            return res              # genuine compile/other failure
        # parse the single suite/test
        for _suite, sd in forged.items():
            for tname, td in sd.get("test_results", {}).items():
                res.test_fn = tname
                res.gas = td.get("kind", {}).get("Standard") if isinstance(td.get("kind"), dict) else None
                res.endpoint = endpoint
                res.logs = td.get("decoded_logs", []) or []
                if td["status"] == "Success":
                    res.passed = True
                    return res
                last_reason = td.get("reason") or "fail"
        if _RPC_ERR.search(last_reason):
            continue                # logic ran but fork-level error -> next endpoint
        res.reason = last_reason
        return res                  # real exploit failure (assertion/revert)
    res.reason = last_reason or "all endpoints failed"
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="single contract id (full or suffix)")
    ap.add_argument("--write", action="store_true", help="mutate dataset JSON in place")
    args = ap.parse_args()

    doc = load_working(DATASET_KEY)
    contracts = [c for c in doc["contracts"] if c["provenance"].get("poc_path")]
    if args.only:
        contracts = [c for c in contracts if c["id"] == args.only or c["id"].endswith(args.only)]
        if not contracts:
            sys.exit(f"no contract matches {args.only!r}")

    results: dict[str, Result] = {}
    for i, c in enumerate(contracts, 1):
        r = run_one(c)
        results[c["id"]] = r
        mark = "PASS" if r.passed else "FAIL"
        print(f"[{i:2}/{len(contracts)}] {mark}  {c['id']:38} "
              f"{CATEGORIES.get(c['id'].split('/')[-1],'?'):26} {r.reason[:50]}")

    npass = sum(1 for r in results.values() if r.passed)
    print(f"\n=== {npass}/{len(results)} exploits reproduced ===")

    SIDECAR.write_text(json.dumps({k: vars(v) for k, v in results.items()}, indent=2))
    print(f"sidecar -> {SIDECAR}")

    if args.write:
        _write_back(doc, results)


def _write_back(doc: dict, results: dict[str, Result]) -> None:
    """Record category + reference-exploit reproduction into the manifest layer.

    Layer-1 is the reference replay: it lands in `manifest.validation.reference_exploit`
    (via the working doc's `provenance.reference_exploit`). It leaves `skip` and the
    fuzzer `poc` (Layer-2) untouched.
    """
    for c in doc["contracts"]:
        cat = CATEGORIES.get(c["id"].split("/")[-1])
        if cat:
            c["category"] = cat
        r = results.get(c["id"])
        if r and r.passed:
            c.setdefault("provenance", {})["reference_exploit"] = {
                "poc_path": r.poc_path,
                "reproduced": True,
                "test_fn": r.test_fn,
                "rpc_endpoint": r.endpoint,
                "logs": r.logs,
            }
    man_path, enr_path = save_working(DATASET_KEY, doc)
    print(f"wrote {man_path.name} + {enr_path.name}")


if __name__ == "__main__":
    main()
