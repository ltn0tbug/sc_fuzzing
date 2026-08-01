#!/usr/bin/env python3
"""Re-validate every runnable SmartBugs-curated PoC against the live fund-flow oracle.

SINGLE SOURCE OF TRUTH = the dataset. For each runnable row (enrich, skip=false)
we take its STORED `poc.calls` + `extend` and run them through the REAL Foundry
harness (`scaffold.prepare` → `FoundryFuzzer.run_input`) — the exact path the
experiment runner uses, so the whole `extend` bag (constructor_args /
constructor_value / pre_deploy / setup_calls / external / setup_template) is wired
identically. No PoCs are authored here: enrich `poc` is canonical (curated
elsewhere); this tool only RE-RUNS what's stored and reports pass/fail.

A PoC PASSES only if a fuzzer account actually nets value —
i.e. our oracle prints `BUG_SIGNAL: attacker_gained …` (reentrancy profit lands on
the unified attacker) or `BUG_SIGNAL: attacker_profit …`. A lone
`target_drained`/`target_loss` (prefunded balance swept to the owner) is a honeypot
artifact, not a true positive.

Usage:
    uv run python utils/validate_pocs.py                 # all runnable rows
    uv run python utils/validate_pocs.py --only <id>
    uv run python utils/validate_pocs.py --cat reentrancy
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import sys
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src" / "experiment" / "dataloader"))
sys.path.insert(0, str(ROOT / "src" / "experiment" / "run"))

from schema import load_dataset  # noqa: E402
from registry import DATASET_SPECS  # noqa: E402
from scaffold import prepare  # noqa: E402
from fuzz.fuzzer.foundry import FoundryFuzzer  # noqa: E402
from fuzz.llm.agent import FuzzInput  # noqa: E402

# A real exploit requires a fuzzer account to PROFIT — a lone target_drained/target_loss
# means the prefund was swept to the owner (honeypot), not stolen. Net-profit vocabulary:
# attacker_gained (reentrancy profit lands on the unified attacker); attacker_profit is
# the value verdict (DEX-priced on a fork, native-only via the mock DEX inline). Match on
# the NAME only.
PROFIT_SIGNALS = {"attacker_gained", "attacker_profit"}


@dataclass
class Outcome:
    id: str
    category: str
    triggered: bool
    signals: list = field(default_factory=list)
    reason: str = ""
    note: str = ""


def run_one(c, ds) -> Outcome:
    """Re-run the dataset's stored PoC for contract `c` through the real harness."""
    rid = c.id
    poc = c.poc or {}
    calls = poc.get("calls")
    if not calls:
        return Outcome(rid, c.category, False, reason="no poc.calls in dataset", note="no-poc")

    # prepare() reads c.extend → ctor_args / pre_deploy / setup_calls / external /
    # setup_template; all are threaded into the FoundryFuzzer below (same as run.py).
    prep = prepare(c, ds)
    if not prep.ok:
        return Outcome(rid, c.category, False,
                       reason=f"{prep.status}: {prep.reason}", note=f"prepare:{prep.status}")

    fz = FoundryFuzzer(
        str(prep.work), prep.target, abi=prep.abi, contract_source=prep.source,
        constructor_args=prep.ctor_args, constructor_value=prep.ctor_value,
        pre_deploy=prep.pre_deploy, setup_calls=prep.setup_calls,
        external=prep.external, setup_template=prep.setup_template,
    )
    if not fz.compile():
        return Outcome(rid, c.category, False, reason="harness compile failed", note="compile-fail")

    fi = FuzzInput(calls=calls, description=poc.get("description", ""))
    res = fz.run_input(fi, strategy=poc.get("strategy", ""), debug=True)
    # Signal NAME only (first token); asset/token_address/total_asset/target_asset/amount
    # are line fields. Dedup.
    signals = sorted({ln.split("BUG_SIGNAL:")[1].strip().split()[0]
                      for ln in res.decoded_logs if "BUG_SIGNAL:" in ln})

    if set(signals) & PROFIT_SIGNALS:
        note = res.forge_status
        expected = set(poc.get("signals") or [])
        if expected and not expected.issubset(set(signals)):
            note += f" (dataset expects {sorted(expected)}, got {sorted(signals)})"
        return Outcome(rid, c.category, True, signals=signals, note=note)
    if signals:  # only target_drained/target_loss → honeypot drain-to-owner
        return Outcome(rid, c.category, False, signals=signals,
                       reason="drain-to-owner only (honeypot, no fuzzer-account profit)",
                       note=f"no-profit/{','.join(signals)}")
    return Outcome(rid, c.category, False,
                   reason=f"no BUG_SIGNAL (forge_status={res.forge_status}, revert={res.revert_reason})",
                   note=f"no-signal/{res.forge_status}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", help="single contract id")
    ap.add_argument("--cat", help="filter by category")
    args = ap.parse_args()

    ds = DATASET_SPECS["smartbugs"]
    recs = load_dataset("smartbugs").contracts   # runnable rows only (skip=false); each has poc + extend
    if args.only:
        recs = [c for c in recs if c.id == args.only]
    if args.cat:
        recs = [c for c in recs if c.category == args.cat]

    outcomes: dict[str, Outcome] = {}
    for c in recs:
        o = run_one(c, ds)
        outcomes[c.id] = o
        tag = "PASS" if o.triggered else "FAIL"
        extra = ",".join(o.signals) if o.triggered else o.reason
        print(f"  [{tag}] {c.id:55} {extra}")

    print("\n=== per-category summary (runnable rows) ===")
    cats = collections.Counter(o.category for o in outcomes.values())
    trig = collections.Counter(o.category for o in outcomes.values() if o.triggered)
    for cat in sorted(cats):
        print(f"  {cat:28} runnable={cats[cat]:2}  pass={trig[cat]:2}  fail={cats[cat]-trig[cat]:2}")
    print(f"  {'TOTAL':28} runnable={sum(cats.values()):2}  pass={sum(trig.values()):2}  "
          f"fail={sum(cats.values())-sum(trig.values()):2}")


if __name__ == "__main__":
    main()
