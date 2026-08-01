"""Per-vulnerability-class detection/coverage breakdown (companion to exp_analysis.py).

Primary purpose: report how each method (esp. SSCFuzz, ours) detects each bug CLASS,
so the scoreboard is directly comparable to FinanceFuzz-style per-class recall.
Reads the same EDA dataframe; writes CSVs to research/figures/vuln_type/.
Run: uv run python src/experiment/eda/vuln_type_analysis.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]      # src/experiment/eda → repo root
sys.path.insert(0, str(ROOT / "src" / "experiment" / "eda"))
import pandas as pd
from dataframe import build_dataframe, METHODS

OUT = ROOT / "research" / "figures" / "vuln_type"; OUT.mkdir(parents=True, exist_ok=True)
df = build_dataframe()
avail = [f"{m}__result_available" for m in METHODS]
paired = df[df[avail].all(axis=1)].copy()

for ds in ("smartbugs", "defihacklabs"):
    sub = paired[paired.dataset == ds]
    rows = []
    for cat, g in sub.groupby(sub["category"].fillna("?")):
        n = len(g)
        row = {"category": cat, "n": n}
        for m in METHODS:
            det = int(g[f"{m}__bug_found_any"].sum())
            row[f"{m}_det"] = det
            row[f"{m}_det_pct"] = round(100 * det / n, 1)
            row[f"{m}_cov"] = round(float(g[f"{m}__bc_cov"].mean()), 3)
        row["union_solved"] = int(g[[f"{m}__bug_found_any" for m in METHODS]].any(axis=1).sum())
        rows.append(row)
    cdf = pd.DataFrame(rows).sort_values("n", ascending=False)
    cdf.to_csv(OUT / f"detection_by_class_{ds}.csv", index=False)
    print(f"\n=== {ds} (N={len(sub)}) ===")
    print(cdf.to_string(index=False))
print(f"\nwrote CSVs to {OUT}")
