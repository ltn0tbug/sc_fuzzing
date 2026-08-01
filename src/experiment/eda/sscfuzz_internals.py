"""Part D — SSCFuzz internals: per-strategy impact + RL-control impact.

Post-hoc on existing logs only (no new sweep). Reads the per-iteration records in
output/experiment/<ds>/sscfuzz/*.json. Each iteration carries strategy/mode +
fallback/fallback_reason, so RL-greedy picks are separable from epsilon-random picks
**inside the same runs** — the epsilon subset is a (uniform) randomized sample of
per-strategy yield, the greedy subset is the policy's realized choices.

Usage:  uv run python src/experiment/eda/sscfuzz_internals.py {defihacklabs|smartbugs|all}

Outputs (research/figures/<experiment|experiment_smartbugs|experiment_combined>/):
  D1_strategy_yield.csv / .png        S1  per-strategy yield (epsilon=unbiased, greedy=realized)
  D2_strategy_by_class.csv / .png     S3  strategy x vuln-class (distinct contracts solved)
  D4_selection_vs_yield.csv / .png    S4  RL selection-share vs strategy yield
  D5_greedy_vs_random.csv / .png              R1  greedy vs epsilon-random, by iteration bin
"""
from __future__ import annotations
import sys, json, collections
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

ROOT = Path(__file__).resolve().parents[3]
DS = sys.argv[1] if len(sys.argv) > 1 else "defihacklabs"
DATASETS = ["defihacklabs", "smartbugs"] if DS in ("all", "combined", "pooled") else [DS]
OUTNAME = ("experiment" if DS == "defihacklabs"
           else "experiment_combined" if len(DATASETS) > 1 else f"experiment_{DS}")
OUT = ROOT / "research" / "figures" / OUTNAME
OUT.mkdir(parents=True, exist_ok=True)
sns.set_theme(style="whitegrid", context="notebook")

sys.path.insert(0, str(ROOT / "src" / "experiment" / "dataloader"))
from schema import load_all as _load_all  # noqa
CAT = {}
for _ds in DATASETS:
    for _c in _load_all(_ds):
        CAT[_c.id] = _c.category or "other"

# Active strategy roster = canonical gen+mut lists MINUS SScFuzz's `disabled_strategies`
# blocklist (source of truth: src/fuzz), so Part D reflects ONLY the strategies that ran
# (5 gen + 4 mut = 9), not the retired full-17 ablation names. Deriving it here keeps Part D
# in lock-step with the RL action table if the roster is re-gated.
sys.path.insert(0, str(ROOT / "src"))
from fuzz.llm.strategies import GENERATION_STRATEGIES, MUTATION_STRATEGIES  # noqa: E402
from fuzz.profiles import sscfuzz_esb_defaults  # noqa: E402
_DISABLED = set(sscfuzz_esb_defaults.disabled_strategies)
GEN = [s for s in GENERATION_STRATEGIES if s not in _DISABLED]
MUT = [s for s in MUTATION_STRATEGIES if s not in _DISABLED]
KIND = {**{s: "gen" for s in GEN}, **{s: "mut" for s in MUT}}
ORDER = GEN + MUT

# ── flatten every sscfuzz iteration into one tidy frame ───────────────────────
rows = []
for ds in DATASETS:
    base = ROOT / "output" / "experiment" / ds / "sscfuzz"
    summ = json.loads((base / "_summary.json").read_text())["results"]
    ok = [r["id"] for r in summ if r.get("status") == "ok"]
    for cid in ok:
        p = base / f"{cid.replace('/', '_')}.json"
        if not p.exists():
            continue
        cat = CAT.get(cid, "other")
        its = json.loads(p.read_text()).get("iterations", [])
        # per-contract iter -> bug, to ask "did the seed we mutated already have the bug?"
        bug_at = {int(it.get("iteration", 0)): bool((it.get("fuzzing_output") or {}).get("bug_found"))
                  for it in its}
        for it in its:
            mode = it.get("mode", "")
            is_mut = mode.startswith("mut")
            strat = (it.get("mutation_strategy") if is_mut else None) or it.get("strategy") or "exploration"
            reason = (it.get("fallback_reason") or "")
            regime = ("random" if it.get("fallback") and "epsilon" in reason
                      else "fallback_other" if it.get("fallback") else "greedy")
            fo = it.get("fuzzing_output") or {}
            bug = bool(fo.get("bug_found", False))
            # genuine = this iteration's call actually created the bug, not inherited from its seed.
            # gen builds from scratch (always genuine if buggy); mut inherits if its immediate
            # seed (lineage[-2]) already tripped the bug.
            if is_mut:
                lin = (it.get("fuzz_input") or {}).get("lineage") or []
                seed_iter = lin[-2].get("iter") if len(lin) >= 2 else None
                seed_bug = bug_at.get(seed_iter, False) if seed_iter is not None else False
            else:
                seed_bug = False
            genuine = bool(bug and not seed_bug)
            rows.append(dict(
                dataset=ds, contract=cid, category=cat, iteration=int(it.get("iteration", 0)),
                kind="mut" if is_mut else "gen", strategy=strat, regime=regime,
                new_bc=float(fo.get("new_bc_branches", 0) or 0),
                reward=float(fo.get("reward", 0) or 0),
                bug=bug, seed_bug=seed_bug, genuine=genuine,
            ))
df = pd.DataFrame(rows)
print(f"[{DS}] iterations: {len(df)}  | regime:", df.regime.value_counts().to_dict())
df.to_csv(OUT / "D0_iterations_tidy.csv", index=False)

def _pal(strats):
    return ["#4C72B0" if KIND.get(s) == "gen" else "#DD8452" for s in strats]

# ── S1: per-strategy yield, epsilon (unbiased) vs greedy (realized) ───────────
def yield_tab(sub):
    g = sub.groupby("strategy").agg(n=("new_bc", "size"), mean_new_bc=("new_bc", "mean"),
                                    mean_reward=("reward", "mean"), bug_rate=("bug", "mean"),
                                    genuine_bug_rate=("genuine", "mean"))
    return g.reindex(ORDER)
s1 = pd.concat({reg: yield_tab(df[df.regime == reg]) for reg in ("random", "greedy")},
               names=["regime"]).round(3)
s1.to_csv(OUT / "D1_strategy_yield.csv")
print("\n=== S1 per-strategy mean new_bc (epsilon-random = unbiased) ===")
print(yield_tab(df[df.regime == "random"])[["n", "mean_new_bc", "bug_rate"]].round(3).to_string())

fig, axes = plt.subplots(1, 2, figsize=(13, 5.5), sharey=True)
for ax, reg, ttl in [(axes[0], "random", "epsilon-random (unbiased yield)"),
                     (axes[1], "greedy", "greedy (realized under policy)")]:
    t = yield_tab(df[df.regime == reg]).fillna(0).reindex(ORDER)
    ax.barh(range(len(ORDER)), t["mean_new_bc"].values, color=_pal(ORDER))
    ax.set_yticks(range(len(ORDER))); ax.set_yticklabels(ORDER)
    for y, (v, n) in enumerate(zip(t["mean_new_bc"].values, t["n"].fillna(0).values)):
        ax.text(v + 0.05, y, f"n={int(n)}", va="center", fontsize=8, color="#555")
    ax.invert_yaxis(); ax.set_xlabel("mean new bc-branches / iter"); ax.set_title(ttl)
fig.suptitle(f"D1 · Per-strategy search yield — {DS}   (blue = generation · orange = mutation)",
             y=1.00, fontsize=14)
plt.tight_layout(); fig.savefig(OUT / "D1_strategy_yield.png", dpi=140, bbox_inches="tight"); plt.close()
print("wrote D1_strategy_yield.png")

# ── S3: strategy x vuln-class — GENUINE only (bug the seed didn't already have) ─
bugs = df[df.genuine]
s3 = (bugs.groupby(["strategy", "category"])["contract"].nunique().rename("n_contracts")
      .reset_index().pivot(index="strategy", columns="category", values="n_contracts")
      .reindex(ORDER).fillna(0).astype(int))
s3.to_csv(OUT / "D2_strategy_by_class.csv")
print("\n=== S3 strategy x class (distinct contracts, GENUINE bug only) ===")
print(s3.loc[(s3.sum(axis=1) > 0)].to_string())
if s3.values.sum():
    fig, ax = plt.subplots(figsize=(1.4 * max(s3.shape[1], 3) + 3, 0.45 * len(ORDER) + 2))
    sns.heatmap(s3, annot=True, fmt="d", cmap="Reds", cbar_kws={"label": "# distinct contracts"},
                linewidths=.5, linecolor="#eee", ax=ax)
    ax.set_title(f"D2 · Strategy that GENUINELY first-found the bug × vuln-class — {DS}\n"
                 "(mutation credited only when its seed had no bug)")
    ax.set_ylabel("strategy (genuine bug-attributed iter)"); ax.set_xlabel("labelled vuln class")
    plt.tight_layout(); fig.savefig(OUT / "D2_strategy_by_class.png", dpi=140, bbox_inches="tight"); plt.close()
    print("wrote D2_strategy_by_class.png")

# ── S5: mutation bug credit — genuine vs inherited ───────────────────────────
mut_bug = df[(df.kind == "mut") & (df.bug)]
g = (mut_bug.assign(kind2=np.where(mut_bug.genuine, "genuine", "inherited"))
     .groupby(["strategy", "kind2"]).size().unstack(fill_value=0)
     .reindex(MUT).fillna(0).astype(int))
for c in ("genuine", "inherited"):
    if c not in g.columns:
        g[c] = 0
g = g[["genuine", "inherited"]]
g["total"] = g.sum(axis=1)
g.to_csv(OUT / "D3_mutation_genuine_vs_inherited.csv")
print("\n=== S5 mutation bug-iters: genuine vs inherited (seed already buggy) ===")
print(g.to_string())
print(f"  TOTAL genuine={int(g['genuine'].sum())}  inherited={int(g['inherited'].sum())}")
fig, ax = plt.subplots(figsize=(8, 5))
yy = range(len(MUT))
ax.barh(yy, g["genuine"].values, color="#2a9d4a", label="genuine (seed had no bug)")
ax.barh(yy, g["inherited"].values, left=g["genuine"].values, color="#d0d0d0",
        label="inherited (seed already buggy → spurious)")
ax.set_yticks(list(yy)); ax.set_yticklabels(MUT); ax.invert_yaxis()
ax.set_xlabel("# mutation iterations reporting a bug"); ax.legend(loc="lower right")
ax.set_title(f"D3 · Mutation bug credit: genuine vs inherited — {DS}\n"
             f"(genuine {int(g['genuine'].sum())} / {int(g['total'].sum())} mutation bug-iters)")
plt.tight_layout(); fig.savefig(OUT / "D3_mutation_genuine_vs_inherited.png", dpi=140, bbox_inches="tight")
plt.close(); print("wrote D3_mutation_genuine_vs_inherited.png")

# ── S4: RL selection-share (greedy) vs unbiased yield (epsilon) ──────────────
greedy = df[df.regime == "greedy"]
share = (greedy.groupby("strategy").size() / len(greedy)).reindex(ORDER).fillna(0)
unbiased = yield_tab(df[df.regime == "random"])["mean_new_bc"].reindex(ORDER).fillna(0)
realized = yield_tab(greedy)["mean_new_bc"].reindex(ORDER).fillna(0)
s4 = pd.DataFrame({"greedy_share": share, "unbiased_yield": unbiased,
                   "realized_yield": realized, "kind": [KIND[s] for s in ORDER]}).round(4)
s4.to_csv(OUT / "D4_selection_vs_yield.csv")
fig, ax = plt.subplots(figsize=(8, 6))
ax.scatter(unbiased.values, share.values, c=_pal(ORDER), s=90, zorder=3)
for s in ORDER:
    ax.annotate(s, (unbiased[s], share[s]), fontsize=8, xytext=(4, 4), textcoords="offset points")
ax.set_xlabel("unbiased yield (mean new bc-branches under epsilon)")
ax.set_ylabel("RL greedy selection share")
ax.set_title(f"D4 · RL selection share vs strategy yield — {DS}\n"
             "(upper-right = correctly favoured · blue gen / orange mut)")
plt.tight_layout(); fig.savefig(OUT / "D4_selection_vs_yield.png", dpi=140, bbox_inches="tight"); plt.close()
print("wrote D4_selection_vs_yield.png")

# ── R1: greedy vs epsilon-random, stratified by iteration bin ────────────────
bins = [0, 20, 40, 60, 80, 100]
labels = ["0-19", "20-39", "40-59", "60-79", "80-99"]
df["bin"] = pd.cut(df["iteration"], bins=bins, right=False, labels=labels)
two = df[df.regime.isin(["greedy", "random"])]
r1 = (two.groupby(["bin", "regime"], observed=True)
      .agg(n=("reward", "size"), mean_reward=("reward", "mean"), mean_new_bc=("new_bc", "mean"))
      .round(3))
r1.to_csv(OUT / "D5_greedy_vs_random.csv")
print("\n=== R1 greedy vs epsilon-random by iteration bin ===")
print(r1.to_string())
fig, axes = plt.subplots(1, 2, figsize=(13, 5))
for ax, col, ttl in [(axes[0], "mean_reward", "mean reward / iter"),
                     (axes[1], "mean_new_bc", "mean new bc-branches / iter")]:
    for reg, c in [("greedy", "#e53935"), ("random", "#9e9e9e")]:
        sub = r1.xs(reg, level="regime").reindex(labels)
        ax.plot(labels, sub[col].values, marker="o", lw=2.5, color=c,
                label=f"{'RL-greedy' if reg == 'greedy' else 'epsilon-random'}")
    ax.set_xlabel("iteration bin"); ax.set_ylabel(col); ax.set_title(ttl); ax.legend()
fig.suptitle(f"D5 · RL-greedy vs ε-random picks (same runs) — {DS}", y=1.01, fontsize=14)
plt.tight_layout(); fig.savefig(OUT / "D5_greedy_vs_random.png", dpi=140, bbox_inches="tight"); plt.close()
print("wrote D5_greedy_vs_random.png")

# ── S6: strategy selection over iterations (realized picks across contracts) ──
n_contracts = df["contract"].nunique()
piv = (df.groupby(["iteration", "strategy"]).size().unstack(fill_value=0)
       .reindex(index=range(100), fill_value=0).reindex(columns=ORDER, fill_value=0))
frac = piv / n_contracts                       # fraction of contracts choosing strat at iter
sm = frac.rolling(window=5, min_periods=1).mean()   # smooth over iterations for display
disp = sm.T.reindex(ORDER)                      # rows = strategy, cols = iteration
frac.T.reindex(ORDER).round(4).to_csv(OUT / "D6_selection_by_iter.csv")
print("\n=== S6 selection-by-iter (gen vs mut share, first/last 20 iters) ===")
gm = frac.assign(gen=frac[GEN].sum(1), mut=frac[MUT].sum(1))[["gen", "mut"]]
print("  iters 0-19 :", gm.iloc[:20].mean().round(3).to_dict())
print("  iters 80-99:", gm.iloc[80:].mean().round(3).to_dict())
fig, ax = plt.subplots(figsize=(13, 6))
sns.heatmap(disp, cmap="magma", vmin=0, cbar_kws={"label": "fraction of contracts (5-iter smoothed)"},
            ax=ax)
ax.axhline(len(GEN), color="#00e5ff", lw=2)    # generation (above) | mutation (below)
ax.set_xticks(range(0, 101, 10)); ax.set_xticklabels(range(0, 101, 10))
ax.set_xlabel("iteration"); ax.set_ylabel("strategy  (gen above cyan line · mut below)")
ax.set_title(f"D6 · Strategy selection over iterations — {DS}\n"
             "(realized picks incl. ε; mutation unlocks once corpus ≥ min size)")
plt.tight_layout(); fig.savefig(OUT / "D6_selection_by_iter.png", dpi=140, bbox_inches="tight"); plt.close()
print("wrote D6_selection_by_iter.png")
print(f"\n[{DS}] Part D done -> {OUT}")
