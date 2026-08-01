"""Part E — oracle precision / signal validity.

Motivation: FinanceFuzz's differential oracle reports a "bug" on a TOD/Gasless/Time
*property difference*, which is NOT the planted vulnerability. We split detected-property
from planted-class, give FF a strict (planted-class-match) vs generous (any-property)
detection rate, and re-derive the union/complementarity with FF's credit corrected.
Also surfaces the PLN heuristic-FP trap (in-house analogue, see oracle_financial_loss_research.md).

Usage:  uv run python src/experiment/eda/oracle_precision.py {defihacklabs|smartbugs|all}
Outputs (research/figures/<experiment|experiment_smartbugs|experiment_combined>/):
  E1_ff_property_by_class.csv / .png   FF detected-property × planted-class
  E1_detection_strict_vs_generous.csv  FF strict (planted-class) vs generous (any) detection
  E2_union_corrected.csv               union / FF-unique under generous vs strict FF crediting
"""
from __future__ import annotations
import sys, json, glob, collections
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

ROOT = Path(__file__).resolve().parents[3]
DS = sys.argv[1] if len(sys.argv) > 1 else "smartbugs"
DATASETS = ["defihacklabs", "smartbugs"] if DS in ("all", "combined", "pooled") else [DS]
OUTNAME = ("experiment" if DS == "defihacklabs"
           else "experiment_combined" if len(DATASETS) > 1 else f"experiment_{DS}")
OUT = ROOT / "research" / "figures" / OUTNAME
OUT.mkdir(parents=True, exist_ok=True)
sns.set_theme(style="whitegrid", context="notebook")
sys.path.insert(0, str(ROOT / "src" / "experiment" / "dataloader"))
from schema import load_all  # noqa

METHODS = ["randomfuzz", "financefuzz", "rlfuzz", "madfuzz", "llmfuzz", "sscfuzz"]
INHOUSE = [m for m in METHODS if m != "financefuzz"]
# FF property -> does it match a planted class in these benchmarks?
ONTARGET = {"Reentrancy": "reentrancy"}     # TOD/Gasless/Timestamp have no planted-class counterpart

def safe(cid): return cid.replace("/", "_")

ff_rows = []                       # FF detections: contract, label, properties, on_target
solved = {m: set() for m in METHODS}          # generous: any bug
ff_solved_strict = set()                       # FF on-target only
for ds in DATASETS:
    cat = {c.id: (c.category or "?") for c in load_all(ds)}
    base = ROOT / "output" / "experiment" / ds
    summ = {m: json.loads((base / m / "_summary.json").read_text())["results"] for m in METHODS}
    ids = {m: {r["id"] for r in summ[m] if r.get("status") == "ok"} for m in METHODS}
    paired = sorted(set.intersection(*ids.values()))
    for m in METHODS:
        by = {r["id"]: r for r in summ[m]}
        for cid in paired:
            if int(by[cid].get("bugs", 0)) > 0:
                solved[m].add(f"{ds}:{cid}")
    # FF property breakdown
    for cid in paired:
        p = base / "financefuzz" / f"{safe(cid)}.json"
        if not p.exists():
            continue
        bugs = json.loads(p.read_text()).get("bugs") or []
        if not bugs:
            continue
        props = sorted({(b.get("bug_type") or "?") for b in bugs})
        label = cat.get(cid, "?")
        on = any(ONTARGET.get(pr) == label for pr in props)
        ff_rows.append(dict(contract=f"{ds}:{cid}", label=label, properties=", ".join(props), on_target=on))
        if on:
            ff_solved_strict.add(f"{ds}:{cid}")

ff = pd.DataFrame(ff_rows)
N = len({f"{ds}:{cid}" for ds in DATASETS
         for cid in (set.intersection(*[{r["id"] for r in json.loads((ROOT/'output'/'experiment'/ds/m/'_summary.json').read_text())['results'] if r.get('status')=='ok'} for m in METHODS]))})

# ── E1: detected-property × planted-class (count of contracts) ────────────────
prop_long = []
for _, r in ff.iterrows():
    for pr in r["properties"].split(", "):
        prop_long.append((pr, r["label"]))
pc = (pd.DataFrame(prop_long, columns=["property", "planted_class"])
      .value_counts().rename("n").reset_index()
      .pivot(index="property", columns="planted_class", values="n").fillna(0).astype(int))
pc.to_csv(OUT / "E1_ff_property_by_class.csv")
print(f"[{DS}] FF detected-property × planted-class (contracts):\n", pc.to_string())

# ── E2: FF strict vs generous detection ──────────────────────────────────────
gen = len(solved["financefuzz"]); strict = len(ff_solved_strict)
e2 = pd.DataFrame({"detection": ["generous (any property)", "strict (planted-class match)"],
                   "n_contracts": [gen, strict], "rate": [gen / N, strict / N]}).round(3)
e2.to_csv(OUT / "E1_detection_strict_vs_generous.csv", index=False)
print(f"\n[{DS}] FF detection  generous={gen}/{N} ({gen/N:.0%})  strict={strict}/{N} ({strict/N:.0%})")
print("  off-target (TOD/Gasless/Time) detections:", gen - strict)

# ── E3: union / complementarity, FF generous vs strict ───────────────────────
union_inhouse = set().union(*[solved[m] for m in INHOUSE])
union_gen = union_inhouse | solved["financefuzz"]
union_strict = union_inhouse | ff_solved_strict
ff_unique_gen = solved["financefuzz"] - union_inhouse
ff_unique_strict = ff_solved_strict - union_inhouse
e3 = pd.DataFrame({
    "quantity": ["5 in-house union", "+FF generous (union)", "+FF strict (union)",
                 "FF unique (generous)", "FF unique (strict)"],
    "n": [len(union_inhouse), len(union_gen), len(union_strict),
          len(ff_unique_gen), len(ff_unique_strict)]})
e3["of_N"] = N
e3.to_csv(OUT / "E2_union_corrected.csv", index=False)
print(f"\n[{DS}] union/complementarity (N={N}):\n", e3.to_string(index=False))
print("  FF unique-generous contracts:", sorted(s.split(':')[-1] for s in ff_unique_gen))
print("  FF unique-strict contracts:  ", sorted(s.split(':')[-1] for s in ff_unique_strict))

# ── figure: property×class heatmap + strict/generous bar ─────────────────────
fig, axes = plt.subplots(1, 2, figsize=(13, 4.8), gridspec_kw={"width_ratios": [2.0, 1]})
sns.heatmap(pc, annot=True, fmt="d", cmap="Oranges", linewidths=.5, linecolor="#eee",
            cbar_kws={"label": "# contracts"}, ax=axes[0])
axes[0].set_title(f"E1 · FinanceFuzz detected property × planted class — {DS}\n"
                  "(only Reentrancy×reentrancy is on-target; TOD/Gasless/Time are off-target)")
axes[0].set_xlabel("planted vuln class"); axes[0].set_ylabel("detected property")
axes[1].bar(["generous\n(any property)", "strict\n(planted-class)"], [gen, strict],
            color=["#bbbbbb", "#2a9d4a"])
for i, v in enumerate([gen, strict]):
    axes[1].text(i, v + 0.1, str(v), ha="center", fontweight="bold")
axes[1].set_title(f"E2 · FF detection (N={N})"); axes[1].set_ylabel("# contracts detected")
plt.tight_layout(); fig.savefig(OUT / "E1_ff_property_by_class.png", dpi=140, bbox_inches="tight")
plt.close(); print(f"\nwrote E1_ff_property_by_class.png -> {OUT}")
