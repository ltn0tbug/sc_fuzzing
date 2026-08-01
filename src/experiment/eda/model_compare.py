"""B1 detection & coverage across LLM model sizes (1.5B / 3B / 7B).

Usage:  python model_compare.py [defihacklabs|smartbugs|all]

Same methodology as `exp_analysis.py` B1 — detection = mean(bugs>0), coverage =
mean(bc_coverage_ratio) from each method's `_summary.json`, restricted to the BASE
paired set (contracts all 6 base methods completed status=ok). Emits the per-model
table the reports' B1 model columns are transcribed from → `B1_by_model.csv` in the
same figure dir as exp_analysis (experiment / experiment_smartbugs / experiment_combined).

Model roots are sibling folders (gitignored `output/`):
  base(1.5B) = output/experiment          (all 6 methods; sscfuzz = symlink → sscfuzz_esb)
  3B         = output/experiment_llama3b  (LLM-driven methods only; sscfuzz dir = sscfuzz_esb)
  7B         = output/experiment_llama7b  (partial run)
RandomFuzz/FinanceFuzz/RLFuzz are LLM-free → identical across sizes (base value reused).
A model-dependent cell (MADFuzz/LLMFuzz/SSCFuzz) is left EMPTY when that model's run does
not cover the whole paired set (absent, partial, or not yet finished).
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
from matplotlib.patches import Patch
from scipy import stats

ROOT = Path(__file__).resolve().parents[3]
DS = sys.argv[1] if len(sys.argv) > 1 else "defihacklabs"
DATASETS = ["defihacklabs", "smartbugs"] if DS in ("all", "combined", "pooled") else [DS]
OUTNAME = ("experiment" if DS == "defihacklabs"
           else "experiment_combined" if len(DATASETS) > 1 else f"experiment_{DS}")
OUT = ROOT / "research" / "figures" / OUTNAME
OUT.mkdir(parents=True, exist_ok=True)

# new report order; LLM-driven methods vary by model size, the rest are LLM-free
METHODS = ["randomfuzz", "financefuzz", "rlfuzz", "madfuzz", "llmfuzz", "sscfuzz"]
LABELS = {"randomfuzz": "RandomFuzz", "financefuzz": "FinanceFuzz", "rlfuzz": "RLFuzz",
          "madfuzz": "MADFuzz", "llmfuzz": "LLMFuzz", "sscfuzz": "SSCFuzz (ours)"}
PALETTE = {"randomfuzz": "#9e9e9e", "financefuzz": "#4db6ac", "rlfuzz": "#ffb74d",
           "madfuzz": "#ba68c8", "llmfuzz": "#64b5f6", "sscfuzz": "#e53935"}
SIZE_ALPHA = {"1.5B": 0.5, "3B": 0.74, "7B": 1.0}   # darker = bigger backend
MODEL_DEP = {"madfuzz", "llmfuzz", "sscfuzz"}
MODELS = {"1.5B": ROOT / "output" / "experiment",
          "3B": ROOT / "output" / "experiment_llama3b",
          "7B": ROOT / "output" / "experiment_llama7b"}
# force-empty cells: model runs known-unusable even if files exist (none at present —
# SSCFuzz-7B completed 2026-07-25; LLMFuzz-7B DeFiHackLabs is only 12/25 and is caught by
# the paired-set completeness check below, so no explicit entry is needed here).
FORCE_EMPTY: set[tuple[str, str]] = set()


def method_dir(root: Path, ds: str, m: str) -> Path:
    name = "sscfuzz_esb" if (m == "sscfuzz" and "experiment_llama" in root.name) else m
    return root / ds / name


def summary(path: Path) -> dict | None:
    p = path / "_summary.json"
    if not p.exists():
        return None
    return {r["id"]: r for r in json.loads(p.read_text())["results"]}


def base_paired(ds: str) -> list[str]:
    base = MODELS["1.5B"]
    idsets = []
    for m in METHODS:
        r = summary(method_dir(base, ds, m)) or {}
        idsets.append({i for i, v in r.items() if v.get("status") == "ok"})
    return sorted(set.intersection(*idsets)) if idsets else []


# paired set = per-dataset base paired sets (pooled = both concatenated)
paired = {ds: base_paired(ds) for ds in DATASETS}
N = sum(len(v) for v in paired.values())

rows = []
for m in METHODS:
    for mn, root in MODELS.items():
        k, det, cov = None, None, None
        if mn != "1.5B" and m not in MODEL_DEP:      # LLM-free → reuse base
            note = "shared (LLM-free)"
        elif (mn, m) in FORCE_EMPTY:
            note = "not finished"
        else:
            got, covered = [], True
            for ds in DATASETS:
                r = summary(method_dir(root, ds, m))
                if r is None:
                    covered = False
                    break
                for cid in paired[ds]:
                    if cid in r and r[cid].get("status") == "ok":
                        got.append(r[cid])
                    else:
                        covered = False
                        break
                if not covered:
                    break
            if not covered or len(got) < N:
                note = "incomplete"
            else:
                k = sum(v.get("bugs", 0) > 0 for v in got)
                det = k / len(got)
                cov = sum(v.get("bc_coverage_ratio", 0) for v in got) / len(got)
                note = ""
        rows.append(dict(method=LABELS[m], model=mn, n=N, k_with_bug=k,
                         detection_rate=det, mean_bc_cov=cov, note=note))

df = pd.DataFrame(rows)
# fill LLM-free rows' 3B/7B from their 1.5B value (identical run reused)
base_val = {r.method: (r.k_with_bug, r.detection_rate, r.mean_bc_cov)
            for r in df[df.model == "1.5B"].itertuples()}
for i, r in df.iterrows():
    if r.note == "shared (LLM-free)":
        df.at[i, "k_with_bug"], df.at[i, "detection_rate"], df.at[i, "mean_bc_cov"] = base_val[r.method]

df.to_csv(OUT / "B1_by_model.csv", index=False)
print(f"[{DS}] paired N={N}  ->  {OUT / 'B1_by_model.csv'}")
piv = df.assign(cell=df.apply(
    lambda r: (f"{r.detection_rate:.0%} / {r.mean_bc_cov:.3f}" if pd.notna(r.detection_rate)
               else f"({r.note})"), axis=1)).pivot(index="method", columns="model", values="cell")
print(piv.reindex([LABELS[m] for m in METHODS])[["1.5B", "3B", "7B"]].to_string())


SIZES = ["1.5B", "3B", "7B"]


# ── B1-by-model: detection & coverage bars, each (method × backend size) its own bar ──
# LLM-free methods = one bar; LLM-driven = one bar per size that covers the paired set
# (darker = bigger backend). This is the B1 figure expanded with the size variants.
bars = []   # (method, size, label, det, cov)
for m in METHODS:
    sizes = SIZES if m in MODEL_DEP else ["1.5B"]
    for s in sizes:
        row = df[(df.method == LABELS[m]) & (df.model == s)]
        if row.empty or pd.isna(row.iloc[0].detection_rate):
            continue                                   # run absent/partial → no bar
        lab = LABELS[m].split(" ")[0] + (f"·{s}" if m in MODEL_DEP else "")
        bars.append((m, s, lab, row.iloc[0].detection_rate, row.iloc[0].mean_bc_cov))

x = np.arange(len(bars))
colors = [PALETTE[m] for m, *_ in bars]
alphas = [SIZE_ALPHA[s] for _, s, *_ in bars]
fig, ax = plt.subplots(1, 2, figsize=(max(11, len(bars) * 0.95), 6))
for i, (_, _, _, det, cov) in enumerate(bars):
    ax[0].bar(i, det, color=colors[i], alpha=alphas[i])
    ax[1].bar(i, cov, color=colors[i], alpha=alphas[i])
    ax[0].text(i, det + .006, f"{det:.0%}", ha="center", fontsize=9, fontweight="bold")
    ax[1].text(i, cov + .008, f"{cov:.1%}", ha="center", fontsize=9, fontweight="bold")
for a, title, ylab, vals in ((ax[0], "Bug Detection Rate", "fraction with ≥1 bug", [b[3] for b in bars]),
                             (ax[1], "Mean Bytecode-Branch Coverage", "coverage ratio", [b[4] for b in bars])):
    a.set_xticks(x); a.set_xticklabels([b[2] for b in bars], fontsize=9, rotation=35, ha="right")
    a.set_title(title); a.set_ylabel(ylab); a.set_ylim(0, max(vals) * 1.25)
    a.tick_params(axis="x", labelsize=9)
plt.suptitle(f"{DS} — detection & coverage by method × LLM backend size "
             f"(darker = bigger backend)", y=1.02, fontsize=14)
plt.tight_layout(); plt.savefig(OUT / "B1_detection_coverage_by_model.png", dpi=150, bbox_inches="tight"); plt.close()
print(f"[{DS}] model detection/coverage bars -> {OUT / 'B1_detection_coverage_by_model.png'}")


# ── B2/B3/B4/B7/B8 expanded: each (method × backend size) that has a complete run is
# its own series. Reads per-iteration result files for coverage curve / first-bug / tokens.
N_ITERS = 100
ENTRIES = [(m, s) for m, s, *_ in bars]                    # complete-run (method,size) pairs
elabel = lambda m, s: LABELS[m].split(" ")[0] + (f"·{s}" if m in MODEL_DEP else "")
ealpha = lambda m, s: SIZE_ALPHA[s] if m in MODEL_DEP else 0.9

sys.path.insert(0, str(ROOT / "src" / "experiment" / "dataloader"))
from schema import load_all as _load_all  # noqa: E402
CAT = {c.id: (c.category or "other") for ds in DATASETS for c in _load_all(ds)}


def per_iter(path: Path):
    d = json.loads(path.read_text()); its = d.get("iterations", [])
    uses_ids = any("coverage_bc_branch_ids" in (it.get("fuzzing_output") or {}) for it in its)
    first_bug, cum = None, []
    if uses_ids:
        seen, total = set(), 0
        for i, it in enumerate(its):
            fo = it.get("fuzzing_output") or {}
            for b in fo.get("coverage_bc_branch_ids", []) or []:
                seen.add(tuple(b))
            total = max(total, int(fo.get("bc_branches_total", 0) or 0))
            cum.append(len(seen))
            if fo.get("bug_found") and first_bug is None:
                first_bug = i
        total = total if total > 0 else max(max(cum, default=1), 1)
        frac = [c / total for c in cum] or [0.0]
    else:
        cov = 0.0
        for i, it in enumerate(its):
            fo = it.get("fuzzing_output") or {}
            cov = max(cov, float(fo.get("coverage", 0) or 0)); cum.append(cov)
            if fo.get("bug_found") and first_bug is None:
                first_bug = i
        frac = cum or [0.0]
    frac = (frac + [frac[-1]] * N_ITERS)[:N_ITERS]
    tokens = (d.get("summary", {}).get("token_usage") or {}).get("total_tokens", 0) or 0
    return np.array(frac), first_bug, int(tokens)


edata = {}   # (m,s) -> per-entry aggregates over the paired set (contract order fixed)
for (m, s) in ENTRIES:
    curves, covs, found, fbs, bugs, toks, cls = [], [], [], [], 0, 0, {}
    for ds in DATASETS:
        summ = summary(method_dir(MODELS[s], ds, m))
        for cid in paired[ds]:
            r = summ[cid]
            covs.append(float(r.get("bc_coverage_ratio", 0)))
            found.append(r.get("bugs", 0) > 0)
            bugs += int(r.get("bugs", 0))
            cls.setdefault(CAT.get(cid, "other"), []).append(r.get("bugs", 0) > 0)
            p = method_dir(MODELS[s], ds, m) / f"{cid.replace('/', '_')}.json"
            if p.exists():
                frac, fb, t = per_iter(p); curves.append(frac); toks += t
                if fb is not None:
                    fbs.append(fb)
            else:
                curves.append(np.zeros(N_ITERS))
    edata[(m, s)] = dict(curve=np.vstack(curves).mean(0), covs=covs, found=found, fbs=fbs,
                         bugs=bugs, tokens=toks, cls=cls, n=len(covs))

# B2 — coverage growth
plt.figure(figsize=(11, 7))
for (m, s) in ENTRIES:
    plt.plot(edata[(m, s)]["curve"], color=PALETTE[m], alpha=ealpha(m, s), lw=2, label=elabel(m, s))
plt.xlabel("iteration"); plt.ylabel("mean cumulative bc-branch coverage")
plt.title(f"{DS} — coverage growth by method × backend size (darker = bigger)")
plt.legend(bbox_to_anchor=(1.01, 1), loc="upper left", fontsize=8, frameon=False)
plt.tight_layout(); plt.savefig(OUT / "B2_coverage_growth_by_model.png", dpi=150, bbox_inches="tight"); plt.close()

# B3 — coverage distribution
fig, ax = plt.subplots(figsize=(max(11, len(ENTRIES) * 0.9), 6))
bp = ax.boxplot([edata[e]["covs"] for e in ENTRIES], patch_artist=True, medianprops=dict(color="black"))
for patch, (m, s) in zip(bp["boxes"], ENTRIES):
    patch.set_facecolor(PALETTE[m]); patch.set_alpha(ealpha(m, s))
ax.set_xticks(range(1, len(ENTRIES) + 1))
ax.set_xticklabels([elabel(*e) for e in ENTRIES], rotation=35, ha="right", fontsize=9)
ax.set_ylabel("bytecode-branch coverage")
ax.set_title(f"{DS} — coverage distribution by method × backend size")
plt.tight_layout(); plt.savefig(OUT / "B3_coverage_box_by_model.png", dpi=150, bbox_inches="tight"); plt.close()

# B4 — time-to-first-bug (Kaplan–Meier: fraction still without a bug)
plt.figure(figsize=(11, 7))
for (m, s) in ENTRIES:
    n = edata[(m, s)]["n"]; fbs = edata[(m, s)]["fbs"]
    surv = [(n - sum(1 for fb in fbs if fb <= t)) / n for t in range(N_ITERS)]
    plt.step(range(N_ITERS), surv, where="post", color=PALETTE[m], alpha=ealpha(m, s), lw=2, label=elabel(m, s))
plt.xlabel("iteration"); plt.ylabel("fraction still without a bug"); plt.ylim(0, 1.02)
plt.title(f"{DS} — time-to-first-bug by method × backend size (lower/earlier = better)")
plt.legend(bbox_to_anchor=(1.01, 1), loc="upper left", fontsize=8, frameon=False)
plt.tight_layout(); plt.savefig(OUT / "B4_time_to_bug_by_model.png", dpi=150, bbox_inches="tight"); plt.close()

# B7 — cost efficiency (bugs per 1k LLM tokens; token-free entries omitted)
cost = [(e, edata[e]["bugs"] / (edata[e]["tokens"] / 1000)) for e in ENTRIES if edata[e]["tokens"] > 0]
if cost:
    fig, ax = plt.subplots(figsize=(max(9, len(cost) * 0.95), 6))
    for i, ((m, s), v) in enumerate(cost):
        ax.bar(i, v, color=PALETTE[m], alpha=ealpha(m, s))
        ax.text(i, v, f"{v:.2f}", ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.set_xticks(range(len(cost)))
    ax.set_xticklabels([elabel(*e) for e, _ in cost], rotation=35, ha="right", fontsize=9)
    ax.set_ylabel("bugs per 1k LLM tokens")
    ax.set_title(f"{DS} — cost efficiency by method × backend size (higher = cheaper per bug)")
    plt.tight_layout(); plt.savefig(OUT / "B7_cost_efficiency_by_model.png", dpi=150, bbox_inches="tight"); plt.close()

# B8 — detection by vulnerability class (rows = class, cols = method×size)
classes = sorted({c for e in ENTRIES for c in edata[e]["cls"]})
mat = np.array([[float(np.mean(edata[e]["cls"][c])) if c in edata[e]["cls"] else np.nan
                 for e in ENTRIES] for c in classes])
fig, ax = plt.subplots(figsize=(0.85 * len(ENTRIES) + 3, 0.6 * len(classes) + 2))
im = ax.imshow(np.ma.masked_invalid(mat), cmap="Greens", vmin=0, vmax=1, aspect="auto")
for ri in range(len(classes)):
    for ci in range(len(ENTRIES)):
        if not np.isnan(mat[ri, ci]):
            ax.text(ci, ri, f"{mat[ri, ci]:.0%}", ha="center", va="center", fontsize=8,
                    color="white" if mat[ri, ci] > 0.5 else "black")
ax.set_xticks(range(len(ENTRIES))); ax.set_xticklabels([elabel(*e) for e in ENTRIES], rotation=35, ha="right", fontsize=9)
ax.set_yticks(range(len(classes))); ax.set_yticklabels(classes, fontsize=9)
ax.set_title(f"{DS} — detection rate by vulnerability class × method × backend size")
fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
plt.tight_layout(); plt.savefig(OUT / "B8_category_detection_by_model.png", dpi=150, bbox_inches="tight"); plt.close()
print(f"[{DS}] expanded B2/B3/B4/B7/B8 -> {OUT}")


# ── B5-by-model: SSCFuzz·1.5B (ours) vs every other (method × backend size) ──────
# paired over the same contract set; Δcov = ours − entry, Cliff's δ + Wilcoxon on
# coverage, McNemar on detection. Each backend size is its own "baseline" row.
def _cliffs(a, b):
    a, b = np.asarray(a), np.asarray(b)
    return (sum(x > y for x in a for y in b) - sum(x < y for x in a for y in b)) / (len(a) * len(b))


def _mcnemar(b, c):
    n = b + c
    return min(2 * stats.binom.cdf(min(b, c), n, 0.5), 1.0) if n else 1.0


REF = ("sscfuzz", "1.5B")
ra, rf = np.array(edata[REF]["covs"]), np.array(edata[REF]["found"])
b5 = []
for e in ENTRIES:
    if e == REF:
        continue
    bcov, bf = np.array(edata[e]["covs"]), np.array(edata[e]["found"])
    diff = ra - bcov
    try:
        wp = stats.wilcoxon(ra, bcov).pvalue if np.any(diff != 0) else 1.0
    except ValueError:
        wp = 1.0
    s_only = int((rf & ~bf).sum()); m_only = int((~rf & bf).sum())
    b5.append(dict(baseline=elabel(*e), d_cov_mean=ra.mean() - bcov.mean(),
                   cliffs_delta=_cliffs(ra, bcov), wilcoxon_p=wp, mcnemar_p=_mcnemar(s_only, m_only)))
b5df = pd.DataFrame(b5)
b5df.to_csv(OUT / "B5_by_model.csv", index=False)
print(f"[{DS}] B5 vs SSCFuzz·1.5B -> {OUT / 'B5_by_model.csv'}\n", b5df.round(3).to_string(index=False))


# ── B6-by-model: bug detection by contract × (method × backend size) ─────────────
# same as the base B6 heatmap (rows = contracts, difficulty-sorted, level-coloured
# labels, SmartBugs by contract name) but columns are every (method × backend size).
try:
    from dataframe import smartbugs_display_names
    _SB = smartbugs_display_names()
except Exception:
    _SB = {}
LEVELS = ["EASY", "NORMAL", "HIGH", "IMPOSSIBLE"]
LRANK = {l: i for i, l in enumerate(LEVELS)}
LCOLOR = {"EASY": "#66bb6a", "NORMAL": "#d4e157", "HIGH": "#ffa726", "IMPOSSIBLE": "#ef5350"}
A4 = pd.read_csv(OUT / "A4_gen_difficulty_dist.csv", index_col=0)


def _a4key(ds, cid):
    stem = cid.split("/")[-1]
    return f"{ds[:2]}:{stem}" if len(DATASETS) > 1 else stem


def _dinfo(ds, cid):
    k = _a4key(ds, cid)
    if k in A4.index:
        return str(A4.loc[k, "level"]), float(A4.loc[k, "self_information_bits"])
    return "EASY", 0.0


def _rlabel(ds, cid):
    stem = cid.split("/")[-1]
    name = _SB.get(stem, stem) if ds == "smartbugs" else stem
    return f"{_dinfo(ds, cid)[0][0]}·{name}"


hrows = sorted([(ds, cid) for ds in DATASETS for cid in paired[ds]],
               key=lambda rc: -(LRANK[_dinfo(*rc)[0]] * 1e6 + _dinfo(*rc)[1]))   # hardest first
HM = np.zeros((len(hrows), len(ENTRIES)))
for ri, (ds, cid) in enumerate(hrows):
    for ci, (m, s) in enumerate(ENTRIES):
        summ = summary(method_dir(MODELS[s], ds, m))
        HM[ri, ci] = 1.0 if (summ and cid in summ and summ[cid].get("bugs", 0) > 0) else 0.0

fig, ax = plt.subplots(figsize=(0.62 * len(ENTRIES) + 4, max(9, len(hrows) * 0.32)))
ax.imshow(HM, cmap=ListedColormap(["#f5f5f5", "#2e7d32"]), vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(len(ENTRIES))); ax.set_xticklabels([elabel(*e) for e in ENTRIES], rotation=35, ha="right", fontsize=9)
ax.set_yticks(range(len(hrows))); ax.set_yticklabels([_rlabel(*rc) for rc in hrows], fontsize=8)
for lab, rc in zip(ax.get_yticklabels(), hrows):
    lab.set_color(LCOLOR[_dinfo(*rc)[0]]); lab.set_fontweight("bold")
ax.set_xticks(np.arange(-.5, len(ENTRIES), 1), minor=True)
ax.set_yticks(np.arange(-.5, len(hrows), 1), minor=True)
ax.grid(which="minor", color="white", linewidth=1); ax.tick_params(which="both", length=0)
for ci in range(1, len(ENTRIES)):                      # thin separators between columns
    ax.axvline(ci - .5, color="white", linewidth=2)
ax.set_title(f"Bug detection by contract × backend size  (filled = ≥1 bug)\n"
             f"{DS} — rows hardest→easiest by difficulty · label colour = level "
             f"(E EASY · N NORMAL · H HIGH · I IMPOSSIBLE)", fontsize=12, pad=12)
ax.legend(handles=[Patch(facecolor=LCOLOR[l], label=l) for l in LEVELS],
          title="difficulty level", loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False, fontsize=9)
plt.tight_layout(); plt.savefig(OUT / "B6_detection_heatmap_by_model.png", dpi=150, bbox_inches="tight"); plt.close()
print(f"[{DS}] B6 detection heatmap by size -> {OUT / 'B6_detection_heatmap_by_model.png'}")

# B6 complementarity per (method × backend size): total solves + unique (solved by
# exactly one entry across all method×size columns). union = contracts solved by ≥1.
per_row = HM.sum(axis=1)
comp = []
for ci, e in enumerate(ENTRIES):
    total = int(HM[:, ci].sum())
    uniq = int(((per_row == 1) & (HM[:, ci] == 1)).sum())
    comp.append(dict(method=elabel(*e), unique_solves=uniq, total_solves=total))
compdf = pd.DataFrame(comp)
union = int((per_row > 0).sum())
compdf.to_csv(OUT / "B6_complementarity_by_model.csv", index=False)
print(f"[{DS}] B6 complementarity (union {union}/{len(hrows)}) -> {OUT / 'B6_complementarity_by_model.csv'}\n",
      compdf.to_string(index=False))
