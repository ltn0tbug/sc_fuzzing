"""Experiment-result + EDA analysis for one dataset sweep.

Usage:  python exp_analysis.py [defihacklabs|smartbugs]

Reads output/experiment/<ds>/<method>/{_summary.json, *.json}, restricts to the
contracts that all 5 methods completed (fair paired set), emits paper-ready
metrics, figures, CSVs, plus an EDA section relating static contract features to
outcomes. SmartBugs runs on whatever is currently finished.
"""
from __future__ import annotations
import json, sys, math
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats

ROOT = Path(__file__).resolve().parents[3]
DS = sys.argv[1] if len(sys.argv) > 1 else "defihacklabs"
# "all"/"combined" pools both datasets into one (N = 25+17). Per-dataset reports
# still live separately; this is the pooled view requested for cross-corpus stats.
DATASETS = ["defihacklabs", "smartbugs"] if DS in ("all", "combined", "pooled") else [DS]
OUTNAME = ("experiment" if DS == "defihacklabs"
           else "experiment_combined" if len(DATASETS) > 1 else f"experiment_{DS}")
OUT = ROOT / "research" / "figures" / OUTNAME
OUT.mkdir(parents=True, exist_ok=True)

METHODS = ["randomfuzz", "financefuzz", "rlfuzz", "madfuzz", "llmfuzz", "sscfuzz"]
LABELS = {"randomfuzz": "RandomFuzz", "llmfuzz": "LLMFuzz", "rlfuzz": "RLFuzz",
          "madfuzz": "MADFuzz", "sscfuzz": "SSCFuzz (ours)", "financefuzz": "FinanceFuzz"}
PALETTE = {"randomfuzz": "#9e9e9e", "llmfuzz": "#64b5f6", "rlfuzz": "#ffb74d",
           "madfuzz": "#ba68c8", "sscfuzz": "#e53935", "financefuzz": "#4db6ac"}
# All methods (incl. FinanceFuzz) now emit per-iter bug_found + coverage_bc_branch_ids,
# so all join the trajectory figures (F2/F4/F10). FinanceFuzz's coverage is sampled once
# per generation (coarser curve, lower-bound cov-AUC).
PER_ITER_METHODS = list(METHODS)
sns.set_theme(style="whitegrid", context="talk")
N_ITERS = 100

def safe_id(cid: str) -> str:        # summary id -> result-file stem
    return cid.replace("/", "_")

# manifest-backed category map (DeFiHackLabs _summary has no category field)
sys.path.insert(0, str(ROOT / "src" / "experiment" / "dataloader"))
from schema import load_all as _load_all  # noqa
CAT = {}
for _ds in DATASETS:
    for _c in _load_all(_ds):
        CAT[_c.id] = _c.category or "other"

def cat_of(r: dict, cid: str) -> str:
    return CAT.get(cid) or r.get("category") or (cid.split("/")[0] if "/" in cid else "other")

def iter_path(ds: str, m: str, cid: str) -> Path:
    # summary id already carries the dataset segment (e.g. "defihacklabs/..", "reentrancy/..")
    # so the result-file stem is just id with "/"→"_". No extra prefix.
    return ROOT / "output" / "experiment" / ds / m / f"{safe_id(cid)}.json"

def per_iter(path: Path):
    d = json.loads(path.read_text())
    its = d.get("iterations", [])
    # Two per-iteration log formats coexist. FinanceFuzz emits a branch-id set
    # (`coverage_bc_branch_ids`) that we accumulate and normalise by bc_branches_total;
    # the in-house methods (random/llm/rl/mad/ssc) instead emit a ready cumulative
    # `coverage` ratio and NO id list. Detect by key presence and build the curve the
    # right way for each — using the id path for both would flat-line the in-house curves.
    uses_ids = any("coverage_bc_branch_ids" in (it.get("fuzzing_output") or {}) for it in its)
    first_bug = None; cum = []
    if uses_ids:
        seen = set(); total = 0
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
            cov = max(cov, float(fo.get("coverage", 0) or 0))  # cumulative bc-branch ratio
            cum.append(cov)
            if fo.get("bug_found") and first_bug is None:
                first_bug = i
        frac = cum or [0.0]
    frac = (frac + [frac[-1]] * N_ITERS)[:N_ITERS]
    return np.array(frac), first_bug

# ── build paired set (per dataset, then pool) ─────────────────────────────────
rows = []; curves = {m: [] for m in PER_ITER_METHODS}
for ds in DATASETS:
    base = ROOT / "output" / "experiment" / ds
    summ = {m: json.loads((base / m / "_summary.json").read_text())["results"] for m in METHODS}
    idsets = {m: {r["id"] for r in summ[m] if r.get("status") == "ok"} for m in METHODS}
    paired = sorted(set.intersection(*idsets.values()))
    print(f"[{ds}] paired contracts (all {len(METHODS)} methods, status ok): {len(paired)}")
    for m in METHODS:
        by_id = {r["id"]: r for r in summ[m]}
        for cid in paired:
            r = by_id[cid]; p = iter_path(ds, m, cid)
            # All methods (incl. FinanceFuzz) now emit per-iter coverage + bug_found.
            frac, first_bug = per_iter(p) if p.exists() else (np.zeros(N_ITERS), None)
            curves[m].append(frac)
            toks = 0
            if p.exists():
                toks = (json.loads(p.read_text()).get("summary", {}).get("token_usage") or {}).get("total_tokens", 0) or 0
            # dataset-tagged key keeps contracts unique across pooled corpora
            key = f"{ds[:2]}:{cid.split('/')[-1]}" if len(DATASETS) > 1 else cid.split("/")[-1]
            rows.append(dict(dataset=ds, method=m, contract=key, category=cat_of(r, cid),
                             bugs=int(r.get("bugs", 0)), found=int(r.get("bugs", 0) > 0),
                             reward=float(r.get("total_reward", 0)), bc_cov=float(r.get("bc_coverage_ratio", 0)),
                             first_bug=first_bug, tokens=int(toks)))
df = pd.DataFrame(rows)
N = df["contract"].nunique()
print(f"[{DS}] POOLED contracts: {N}")
contracts = sorted(df["contract"].unique())
df.to_csv(OUT / "tidy_results.csv", index=False)

# ── PoC-derived generation difficulty (method-independent) ────────────────────
# UNIFIED measure = Shannon self-information of the exploit trace:
#     H = -log2 P(a maximum-entropy fuzzer reproduces the exploit in one draw)
#       = log2(search-space size)   [ETHPLOIT/EF-CF/ItyFuzz "functions x args x seq"]
# Intrinsic (bits); NOT tied to any iteration budget. Every pool size below is a
# MEASURED data feature (build_dataframe) or read off the PoC — no hand weights.
#   H = sum over calls of [ log2(F) + (caller? log2(A)) + sum_args log2(pool_arg) ]
#     F     = external_fn_count                 (ABI surface: which function)
#     A     = # distinct actors in the PoC + 1  (which msg.sender / access control)
#     addr  = 2 + hardcoded_address_count + |extend.external|  (seeded address corpus)
#     const = magic_number_count + 2            (contract's own constant pool)
#     $ret / raw-address needle = FULL TYPE DOMAIN (2^256 / 2^160) -> no static pool
#            supplies it => the runtime-dataflow capability current blind fuzzers
#            lack => IMPOSSIBLE emerges from the math, not a hand gate.
# Bands: IMPOSSIBLE = any full-domain coordinate; EASY/NORMAL/HIGH = data-driven
# tertiles of H over all 58 non-impossible contracts (stable across all reports).
import math
_ENRICH_DIR = {"defihacklabs": "defihacklabs", "smartbugs": "smartbugs_curated"}
import re as _re
sys.path.insert(0, str(ROOT / "src" / "experiment" / "eda"))
from dataframe import build_dataframe as _build_df  # noqa
_FDF = _build_df()
_FEAT = {}   # (dataset, segment) -> feature row
for _, _r in _FDF.iterrows():
    _FEAT[(_r["dataset"], str(_r["contract_id"]).split("/")[-1].replace(".sol", ""))] = _r
DOM_ADDR, DOM_UINT = 160.0, 256.0   # exact type domains in bits: |address|=2^160, |uint256|=2^256

# Difficulty is anchored to RANDOMFUZZ reachability: a coordinate costs log2(pool) if
# RandomFuzz can draw a satisfying value, and is IMPOSSIBLE if it cannot. RandomFuzz draws
# numeric args ONLY from these boundary/scale pools (fuzzer.random_gen), so a required value
# outside them — e.g. a keccak-derived storage slot — is unreachable by blind sampling.
sys.path.insert(0, str(ROOT / "src"))
from fuzz.llm.random_gen import _UINT_VALUES as _RF_UINT, _INT_VALUES as _RF_INT  # noqa: E402
_RF_BIG = {abs(int(v)) for v in (_RF_UINT + _RF_INT) if abs(int(v)) >= 2**32}  # large values RF actually draws
def _num_reachable(v: int) -> bool:
    """True iff RandomFuzz's boundary/scale pool can produce this literal. Small/medium
    values (< 2^32) are treated as reachable (any-small-value or the contract magic pool);
    a large value is reachable only if it is one of RandomFuzz's boundary/scale constants."""
    v = abs(int(v))
    return v < 2**32 or v in _RF_BIG
def _feat_num(feat, col, default):
    try:
        v = feat[col]; return int(v) if v == v else default   # NaN-safe
    except Exception:
        return default
def _arg_kind(t):
    if isinstance(t, bool):                                   return "free"
    if isinstance(t, int):
        if t in (0, 1) or abs(t) < 64:                        return "free"
        return "const" if _num_reachable(t) else "value_needle"
    s = str(t)
    if s.startswith("$ret"):                                  return "dataflow"     # runtime-derived
    if s in ("max", "now"):                                   return "const"
    if s in ("reentrancy_address", "attacker", "reentrancy"): return "free"         # attacker addr (given)
    if _re.fullmatch(r"0x0+", s):                             return "free"
    if _re.fullmatch(r"0x0*dead", s, _re.I):                 return "free"         # 0x…dEaD burn = arbitrary recipient, not a needle
    if s.startswith(("attacker_addr", "target_address", "reentrant_", "max_count")): return "free"
    if _re.fullmatch(r"(true|false)", s):                     return "free"
    if _re.fullmatch(r"0x[0-9a-fA-F]{40}", s):                return "needle"       # raw address literal (specific unknown on-chain addr)
    if _re.fullmatch(r"0x[0-9a-fA-F]+", s):                                         # numeric hex literal
        return "const" if _num_reachable(int(s, 16)) else "value_needle"           # keccak slot / arbitrary big value = unreachable
    if _re.fullmatch(r"\d+", s):
        return "free" if int(s) < 64 else ("const" if _num_reachable(int(s)) else "value_needle")
    return "addr"     # a named external var -> drawn from the seeded address corpus
def _self_info(c, feat):
    """Return (H_bits, impossible). H = log2 search-space size; impossible = needs a
    full-domain value no static pool supplies ($ret dataflow / raw-address needle)."""
    calls = c["poc"].get("calls", [])
    E = len(c.get("extend", {}).get("external", []))
    P_fn    = max(2, _feat_num(feat, "external_fn_count", _feat_num(feat, "total_fn_count", 2)))
    P_addr  = max(2, 2 + _feat_num(feat, "hardcoded_address_count", 0) + E)
    P_const = max(2, _feat_num(feat, "magic_number_count", 0) + 2)
    P_actor = max(2, len({str(cl[3]) for cl in calls if len(cl) > 3}) + 1)
    bits = 0.0; impossible = False
    for cl in calls:
        name = cl[0] if cl else ""
        if not (isinstance(name, str) and "reentr" in name.lower()):
            bits += math.log2(P_fn)                                   # which function
        caller = str(cl[3]) if len(cl) > 3 else "attacker"
        if caller not in ("attacker", "reentrancy_address", "reentrancy", ""):
            bits += math.log2(P_actor)                                # which sender (access control)
        val = str(cl[2]) if len(cl) > 2 else "0"
        if not _re.fullmatch(r"0x0*|0", val):
            bits += math.log2(P_const)                                # specific msg.value
        def _arg_bits(a):
            """(bits, impossible) for one argument, recursing into arrays. RandomFuzz emits
            only LENGTH-1 arrays (random_gen.random_arg_for_type), so a PoC array of length
            ≥ 2 is unreachable → IMPOSSIBLE."""
            if isinstance(a, list):
                if len(a) >= 2:   return DOM_UINT, True        # multi-element array RandomFuzz can't build
                if len(a) == 1:   return _arg_bits(a[0])       # length-1 array = its single element
                return 0.0, False                              # empty array -> new T[](0)
            k = _arg_kind(a)
            if   k == "addr":         return math.log2(P_addr), False
            elif k == "const":        return math.log2(P_const), False
            elif k == "needle":       return DOM_ADDR, True    # specific unknown on-chain address
            elif k == "value_needle": return DOM_UINT, True    # value RandomFuzz can't draw (keccak slot / arbitrary big)
            elif k == "dataflow":     return DOM_UINT, True    # runtime-derived ($ret)
            return 0.0, False                                  # free
        for a in (cl[1] if len(cl) > 1 else []):
            _b, _im = _arg_bits(a); bits += _b; impossible = impossible or _im
    return bits, impossible

# score ALL 58 (both datasets) so the tertile band-edges are stable across reports
_ds_pre = {"defihacklabs": "de", "smartbugs": "sm"}
_ALL = {}   # key (report-format) -> (bits, impossible, dataset)
for _ds in ["defihacklabs", "smartbugs"]:
    for _c in json.loads((ROOT / "data" / _ENRICH_DIR[_ds] / "enrich.json").read_text())["contracts"]:
        _seg = _c["id"].split("/")[-1]
        _feat = _FEAT.get((_ds, _seg), {})
        _b, _imp = _self_info(_c, _feat)
        _key = f"{_ds_pre[_ds]}:{_seg}" if len(DATASETS) > 1 else _seg
        _ALL[(_ds, _seg)] = (_b, _imp, _key)
_finite = sorted(b for b, imp, _ in _ALL.values() if not imp)
_q33, _q66 = np.quantile(_finite, [1/3, 2/3])   # data-driven band edges (no chosen constant)
def _level(bits, imp):
    if imp:            return "IMPOSSIBLE"
    if bits <= _q33:   return "EASY"
    if bits <= _q66:   return "NORMAL"
    return "HIGH"

LEVELS = ["EASY", "NORMAL", "HIGH", "IMPOSSIBLE"]
LEVEL_RANK  = {l: i for i, l in enumerate(LEVELS)}
LEVEL_COLOR = {"EASY": "#66bb6a", "NORMAL": "#d4e157", "HIGH": "#ffa726", "IMPOSSIBLE": "#ef5350"}
DIFF = {}   # contract-key -> (level, bits, impossible)
for (_ds, _seg), (_b, _imp, _key) in _ALL.items():
    if _ds in DATASETS:
        DIFF[_key] = (_level(_b, _imp), _b, _imp)
diff_level = pd.Series({k: v[0] for k, v in DIFF.items()})
diff_bits  = pd.Series({k: v[1] for k, v in DIFF.items()})
diff_key   = pd.Series({k: LEVEL_RANK[v[0]] * 1e6 + v[1] for k, v in DIFF.items()})

# ── A4: sample difficulty distribution (dataset property; no method outcomes) ──
order_a4 = diff_key.reindex(contracts).dropna().sort_values().index
pop = {l: int((diff_level.reindex(contracts) == l).sum()) for l in LEVELS}
_fin_max = max([diff_bits[k] for k in order_a4 if DIFF[k][2] is False] or [1.0])
_cap = _fin_max * 1.18                              # display cap for infeasible bars (2^256 would dwarf all)
heights = [(_cap if DIFF[k][2] else diff_bits[k]) for k in order_a4]
plt.figure(figsize=(max(8, len(order_a4) * 0.17), 5))
plt.bar(range(len(order_a4)), heights,
        color=[LEVEL_COLOR[diff_level[k]] for k in order_a4], width=0.9)
plt.axhline(_q33, ls=":", c="grey", lw=1); plt.axhline(_q66, ls=":", c="grey", lw=1)
plt.text(len(order_a4) * 0.98, _cap, "IMPOSSIBLE capped (true H ≥ 160 bits) ", va="bottom", ha="right",
         fontsize=8, color="#b71c1c")
plt.xlabel("contracts (one bar each; sorted by difficulty level then self-information)")
plt.ylabel("self-information  H = log2(search space)\n(bits; expected random draws = 2^H)")
plt.title(f"Sample difficulty distribution ({DS}, N={len(order_a4)})")
from matplotlib.patches import Patch
plt.legend(handles=[Patch(facecolor=LEVEL_COLOR[l], label=f"{l} (n={pop[l]})")
                    for l in LEVELS if pop[l]], frameon=False, loc="upper left")
plt.xticks([])
plt.tight_layout(); plt.savefig(OUT / "A4_gen_difficulty_dist.png", dpi=150, bbox_inches="tight"); plt.close()
pd.DataFrame({"level": diff_level.reindex(contracts), "self_information_bits": diff_bits.reindex(contracts).round(2),
              "impossible": pd.Series({k: v[2] for k, v in DIFF.items()}).reindex(contracts)}
             ).to_csv(OUT / "A4_gen_difficulty_dist.csv")

# ── headline ──────────────────────────────────────────────────────────────────
auc = {m: np.vstack(curves[m]).mean(axis=1).mean() for m in PER_ITER_METHODS}
mean_curve = {m: np.vstack(curves[m]).mean(axis=0) for m in PER_ITER_METHODS}
def agg(m):
    g = df[df.method == m]; bi = g["first_bug"].dropna()
    return dict(method=LABELS[m], detection_rate=g["found"].mean(),
                contracts_with_bug=int(g["found"].sum()), total_bugs=int(g["bugs"].sum()),
                mean_bugs=g["bugs"].mean(), mean_bc_cov=g["bc_cov"].mean(),
                median_bc_cov=g["bc_cov"].median(), mean_reward=g["reward"].mean(),
                median_ttfb=bi.median() if len(bi) else np.nan, coverage_auc=auc.get(m, np.nan),
                tokens_total=int(g["tokens"].sum()),
                bugs_per_1k_tok=(g["bugs"].sum()/(g["tokens"].sum()/1000)) if g["tokens"].sum() else np.nan)
summary = pd.DataFrame([agg(m) for m in METHODS]).set_index("method")
summary.to_csv(OUT / "01_headline_metrics.csv")
print("\n=== HEADLINE ===\n", summary.round(3).to_string())

piv_cov = df.pivot(index="contract", columns="method", values="bc_cov").loc[contracts, METHODS]
piv_found = df.pivot(index="contract", columns="method", values="found").loc[contracts, METHODS]

# ── paired stats vs sscfuzz ───────────────────────────────────────────────────
def cliffs(a, b):
    a, b = np.asarray(a), np.asarray(b)
    return (sum(x > y for x in a for y in b) - sum(x < y for x in a for y in b)) / (len(a)*len(b))
def mcnemar(b, c):
    n = b + c
    return min(2*stats.binom.cdf(min(b, c), n, 0.5), 1.0) if n else 1.0
stat_rows = []
for m in METHODS:
    if m == "sscfuzz": continue
    a = piv_cov["sscfuzz"].values; b = piv_cov[m].values
    nz = (a - b)[a - b != 0]
    try: wp = stats.wilcoxon(a, b).pvalue if len(nz) else 1.0
    except ValueError: wp = 1.0
    s_only = int(((piv_found["sscfuzz"]==1)&(piv_found[m]==0)).sum())
    m_only = int(((piv_found["sscfuzz"]==0)&(piv_found[m]==1)).sum())
    stat_rows.append(dict(baseline=LABELS[m], d_cov_mean=a.mean()-b.mean(),
                          d_cov_median=np.median(a)-np.median(b), wilcoxon_p=wp,
                          cliffs_delta_cov=cliffs(a, b), bug_sscfuzz_only=s_only,
                          bug_baseline_only=m_only, mcnemar_p=mcnemar(s_only, m_only)))
stats_df = pd.DataFrame(stat_rows).set_index("baseline")
stats_df.to_csv(OUT / "02_paired_stats_vs_sscfuzz.csv")
print("\n=== PAIRED STATS ===\n", stats_df.round(4).to_string())

# ── complementarity ───────────────────────────────────────────────────────────
comp = []
for m in METHODS:
    others = [x for x in METHODS if x != m]
    only = int(((piv_found[m]==1)&(piv_found[others].sum(axis=1)==0)).sum())
    comp.append(dict(method=LABELS[m], unique_contracts=only, total_found=int(piv_found[m].sum())))
comp_df = pd.DataFrame(comp).set_index("method")
union_solv = int((piv_found.sum(axis=1) > 0).sum())
comp_df.to_csv(OUT / "03_complementarity.csv")
print(f"\n=== COMPLEMENTARITY === union solvable {union_solv}/{N}\n", comp_df.to_string())

# =============================================================================
#  FIGURES (method comparison)
# =============================================================================
order = METHODS; colors = [PALETTE[m] for m in order]; labels = [LABELS[m] for m in order]
TITLE = (f"Pooled corpus — SmartBugs ∪ DeFiHackLabs (N={N})" if len(DATASETS) > 1
         else f"{DS} sweep (N={N}, 100 iters/contract)")

fig, ax = plt.subplots(1, 2, figsize=(15, 6))
dr = [summary.loc[LABELS[m], "detection_rate"] for m in order]
ax[0].bar(labels, dr, color=colors)
for i, v in enumerate(dr): ax[0].text(i, v+.005, f"{v:.0%}", ha="center", fontweight="bold")
ax[0].set_title("Bug Detection Rate"); ax[0].set_ylabel("fraction with ≥1 bug")
ax[0].set_ylim(0, max(dr)*1.25 or 1); ax[0].tick_params(axis='x', rotation=20)
cv = [summary.loc[LABELS[m], "mean_bc_cov"] for m in order]
ce = [df[df.method==m]["bc_cov"].sem() for m in order]
ax[1].bar(labels, cv, yerr=ce, color=colors, capsize=4)
for i, v in enumerate(cv): ax[1].text(i, v+.01, f"{v:.1%}", ha="center", fontweight="bold")
ax[1].set_title("Mean Bytecode-Branch Coverage"); ax[1].set_ylabel("coverage ratio")
ax[1].set_ylim(0, max(cv)*1.25); ax[1].tick_params(axis='x', rotation=20)
plt.suptitle(TITLE, y=1.02, fontsize=18); plt.tight_layout()
plt.savefig(OUT / "B1_detection_coverage.png", dpi=150, bbox_inches="tight"); plt.close()

plt.figure(figsize=(11, 7))
# FinanceFuzz curve is coarser (coverage sampled once per generation, not per eval).
for m in PER_ITER_METHODS: plt.plot(range(1, N_ITERS+1), mean_curve[m], label=LABELS[m], color=PALETTE[m], lw=2.5)
plt.xlabel("iteration"); plt.ylabel("mean cumulative bc-branch coverage")
plt.title(f"Coverage Growth (mean over N={N}; FinanceFuzz sampled per-generation)")
plt.legend(loc="lower right", fontsize=13)
plt.tight_layout(); plt.savefig(OUT / "B2_coverage_growth.png", dpi=150, bbox_inches="tight"); plt.close()

plt.figure(figsize=(12, 7))
sns.boxplot(data=df, x="method", y="bc_cov", order=order, hue="method", palette=PALETTE, legend=False, showfliers=False)
sns.stripplot(data=df, x="method", y="bc_cov", order=order, color=".25", size=4, alpha=.5)
plt.xticks(range(len(order)), labels, rotation=20); plt.xlabel(""); plt.ylabel("bytecode-branch coverage")
plt.title("Per-Contract Coverage Distribution"); plt.tight_layout()
plt.savefig(OUT / "B3_coverage_box.png", dpi=150, bbox_inches="tight"); plt.close()

plt.figure(figsize=(11, 7))
for m in PER_ITER_METHODS:
    fb = df[df.method == m]["first_bug"].values
    surv = [1 - np.sum([(x is not None and not (isinstance(x, float) and math.isnan(x)) and x <= t) for x in fb])/N for t in range(N_ITERS)]
    plt.step(range(1, N_ITERS+1), surv, where="post", label=LABELS[m], color=PALETTE[m], lw=2.5)
plt.xlabel("iteration"); plt.ylabel("fraction WITHOUT a bug yet"); plt.ylim(0, 1.02)
plt.title("Time-to-First-Bug (Kaplan–Meier)")
plt.legend(fontsize=13); plt.tight_layout()
plt.savefig(OUT / "B4_time_to_bug.png", dpi=150, bbox_inches="tight"); plt.close()

best_base = max([m for m in METHODS if m!="sscfuzz"], key=lambda m: summary.loc[LABELS[m], "mean_bc_cov"])
plt.figure(figsize=(8.5, 8))
x = piv_cov[best_base].values; y = piv_cov["sscfuzz"].values; lim = max(x.max(), y.max(), .01)*1.05
plt.scatter(x, y, c=[PALETTE["sscfuzz"]], s=80, alpha=.7, edgecolors="k")
plt.plot([0, lim], [0, lim], "k--", alpha=.5)
plt.xlabel(f"{LABELS[best_base]} coverage"); plt.ylabel("SSCFuzz coverage")
win = int((y > x).sum()); tie = int((y == x).sum())
plt.title("Head-to-head coverage\n(above line = SSCFuzz wins)")
plt.text(.05*lim, .9*lim, f"SSCFuzz wins {win}/{N}\nties {tie}", fontsize=14,
         bbox=dict(boxstyle="round", fc="white", alpha=.8))
plt.tight_layout(); plt.savefig(OUT / "B5_head_to_head.png", dpi=150, bbox_inches="tight"); plt.close()

hm = piv_found.copy(); hm.columns = [LABELS[m] for m in hm.columns]
# SmartBugs rows are named by on-chain address; relabel with the source's primary contract
# name so the heatmap reads by contract. DeFiHackLabs keys are already readable (date_name).
try:
    from dataframe import smartbugs_display_names
    _SB_DISP = smartbugs_display_names()
except Exception:
    _SB_DISP = {}
def _disp(k: str) -> str:
    stem = k.split(":", 1)[-1] if ":" in k else k   # strip pooled 'sm:'/'de:' prefix
    return _SB_DISP.get(stem, stem)
# sort rows by PoC difficulty (hardest first = level then self-information); prefix each with level initial
_ord = list(diff_key.reindex(hm.index).sort_values(ascending=False, na_position="last").index)
hm = hm.loc[_ord]
_row_levels = [diff_level.get(k, "EASY") for k in _ord]
hm.index = [f"{diff_level.get(k, '?')[0]}·{_disp(k)}" for k in _ord]   # E/N/H/I = EASY/NORMAL/HIGH/IMPOSSIBLE
fig, ax = plt.subplots(figsize=(1.15*len(hm.columns) + 6.5, max(10, N*0.5)))
sns.heatmap(hm, cmap=["#f5f5f5", "#2e7d32"], cbar=False, linewidths=1.0, linecolor="white", ax=ax)
ax.set_title("Bug detection by contract  (filled = ≥1 bug found)\n"
             "rows hardest→easiest by difficulty · row-label colour = level (E EASY · N NORMAL · H HIGH · I IMPOSSIBLE)",
             fontsize=14, pad=16)
ax.set_xlabel(""); ax.set_ylabel("")
ax.tick_params(axis="y", labelsize=11, length=0)
ax.tick_params(axis="x", labelsize=13, length=0)
plt.setp(ax.get_xticklabels(), rotation=30, ha="right", fontweight="bold")
for _lab, _lvl in zip(ax.get_yticklabels(), _row_levels):   # colour each contract label by its level
    _lab.set_color(LEVEL_COLOR[_lvl]); _lab.set_fontweight("bold")
# level legend
from matplotlib.patches import Patch as _Patch
ax.legend(handles=[_Patch(facecolor=LEVEL_COLOR[l], label=l) for l in LEVELS],
          title="difficulty level", loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False, fontsize=11)
plt.tight_layout(); plt.savefig(OUT / "B6_detection_heatmap.png", dpi=150, bbox_inches="tight"); plt.close()

llm_m = [m for m in order if summary.loc[LABELS[m], "tokens_total"] > 0]
if llm_m:
    plt.figure(figsize=(10, 6))
    eff = [summary.loc[LABELS[m], "bugs_per_1k_tok"] for m in llm_m]
    plt.bar([LABELS[m] for m in llm_m], eff, color=[PALETTE[m] for m in llm_m])
    for i, v in enumerate(eff): plt.text(i, v, f"{v:.3f}", ha="center", va="bottom", fontweight="bold")
    plt.ylabel("bugs per 1k LLM tokens"); plt.title("LLM Cost Efficiency"); plt.xticks(rotation=20)
    plt.tight_layout(); plt.savefig(OUT / "B7_cost_efficiency.png", dpi=150, bbox_inches="tight"); plt.close()

cat_tab = df.groupby(["category", "method"])["found"].sum().unstack().reindex(columns=order).fillna(0)
cat_tab.columns = [LABELS[m] for m in order]
cat_tab = cat_tab.loc[cat_tab.sum(axis=1).sort_values(ascending=False).index]
cat_tab.to_csv(OUT / "08_detection_by_category.csv")
ax = cat_tab.plot(kind="barh", figsize=(12, max(5, len(cat_tab)*0.6)), color=[PALETTE[m] for m in order])
ax.set_xlabel("contracts with ≥1 bug"); ax.set_ylabel(""); ax.set_title("Bug Detection by Vulnerability Category")
plt.legend(fontsize=11); plt.tight_layout()
plt.savefig(OUT / "B8_category_detection.png", dpi=150, bbox_inches="tight"); plt.close()

# ── F9: action-selection heatmaps (3 heads) ───────────────────────────────────
# THREE action spaces. (1) generation strategy (per-iter `strategy`): SSCFuzz=RL,
# LLMFuzz=uniform cycle. (2) function group (per-iter `group_name`): RLFuzz=RL,
# MADFuzz=policy. (3) mutation strategy (per-iter `mutation_strategy`): SSCFuzz-only
# RL head — applied to a seed in ~28% of iters ("none" = pure generation).
# RandomFuzz has none (uniform fn pick) → excluded. Cells = fraction of that
# method's iterations spent on each action (column-normalised), over the paired set.
from collections import Counter as _Counter
_strat_methods = ["sscfuzz", "llmfuzz"]
_group_methods = ["rlfuzz", "madfuzz"]
_mut_methods = ["sscfuzz", "llmfuzz"]  # LLMFuzz also mutates seeds (value_perturb/call_swap/…), not gen-only
_strat_cnt = {m: _Counter() for m in _strat_methods}
_group_cnt = {m: _Counter() for m in _group_methods}
_mut_cnt = {m: _Counter() for m in _mut_methods}
for _ds in DATASETS:
    _base = ROOT / "output" / "experiment" / _ds
    _summ = {m: json.loads((_base / m / "_summary.json").read_text())["results"] for m in METHODS}
    _ids = {m: {r["id"] for r in _summ[m] if r.get("status") == "ok"} for m in METHODS}
    for cid in sorted(set.intersection(*_ids.values())):
        for m in set(_strat_methods + _group_methods + _mut_methods):
            p = iter_path(_ds, m, cid)
            if not p.exists():
                continue
            for it in json.loads(p.read_text()).get("iterations", []):
                if m in _strat_cnt and it.get("strategy"):
                    _strat_cnt[m][it["strategy"]] += 1
                if m in _group_cnt and it.get("group_name"):
                    _group_cnt[m][it["group_name"]] += 1
                if m in _mut_cnt:
                    _mut_cnt[m][it.get("mutation_strategy") or "none (pure gen)"] += 1

def _sel_table(cnt, methods):
    keys = sorted({k for m in methods for k in cnt[m]}, key=lambda k: -sum(cnt[m][k] for m in methods))
    tab = pd.DataFrame({LABELS[m]: [cnt[m].get(k, 0) for k in keys] for m in methods}, index=keys)
    return tab.div(tab.sum(axis=0).replace(0, 1), axis=1)  # column-normalise to fractions

strat_tab = _sel_table(_strat_cnt, _strat_methods)
group_tab = _sel_table(_group_cnt, _group_methods)
mut_tab = _sel_table(_mut_cnt, _mut_methods)
strat_tab.to_csv(OUT / "09_strategy_selection.csv")
group_tab.to_csv(OUT / "09b_group_selection.csv")
mut_tab.to_csv(OUT / "09c_mutation_selection.csv")
_panels = [(strat_tab, "Generation strategy\n(SSCFuzz=RL · LLMFuzz=cycle)"),
           (group_tab, "Function group\n(RLFuzz=RL · MADFuzz=policy)"),
           (mut_tab, "Mutation strategy\n(SSCFuzz RL · LLMFuzz cycle)")]
if any(len(t) for t, _ in _panels):
    nrow = max([len(t) for t, _ in _panels] + [1])
    fig, axes = plt.subplots(1, 3, figsize=(16, max(4.5, 0.5 * nrow + 1.5)),
                             gridspec_kw={"width_ratios": [max(1, t.shape[1]) for t, _ in _panels]})
    for ax, (tab, ttl) in zip(axes, _panels):
        if len(tab):
            sns.heatmap(tab, ax=ax, cmap="rocket_r", annot=True, fmt=".2f", cbar=False,
                        vmin=0, vmax=max(0.5, float(tab.values.max())), linewidths=.5, linecolor="white")
        else:
            ax.text(.5, .5, "no data", ha="center", va="center"); ax.set_axis_off()
        ax.set_title(ttl, fontsize=12); ax.set_xlabel(""); ax.set_ylabel(""); ax.tick_params(axis="x", rotation=15)
    fig.suptitle(f"Action selection — {DS} (frac of iterations, N={N})", fontsize=15)
    plt.tight_layout(); plt.savefig(OUT / "B9_selection_heatmap.png", dpi=150, bbox_inches="tight"); plt.close()
print("\n=== GENERATION STRATEGY (frac of iters) ===\n", strat_tab.round(3).to_string())
print("\n=== FUNCTION-GROUP SELECTION (frac of iters) ===\n", group_tab.round(3).to_string())
print("\n=== MUTATION STRATEGY (frac of iters, sscfuzz + llmfuzz) ===\n", mut_tab.round(3).to_string())

# ── F10: test-case SHAPE that finds bugs — sequence depth × width → bug-rate ───
# Per generated input: depth = #calls in the tx sequence, width = #distinct
# functions touched. Cell = bug-rate (fraction of inputs of that shape whose run
# set fuzzing_output.bug_found), pooled over the 5 methods, paired set. Answers
# "what shape of test case actually triggers bugs?" — independent of which contract.
DEPTH_BINS = [(1, 1, "1"), (2, 3, "2-3"), (4, 5, "4-5"), (6, 8, "6-8"), (9, 99, "9+")]
WIDTH_BINS = [(1, 1, "1"), (2, 2, "2"), (3, 3, "3"), (4, 5, "4-5"), (6, 99, "6+")]
dw_bug = np.zeros((len(DEPTH_BINS), len(WIDTH_BINS)))
dw_tot = np.zeros((len(DEPTH_BINS), len(WIDTH_BINS)))
for _ds in DATASETS:
    _base = ROOT / "output" / "experiment" / _ds
    _summ = {m: json.loads((_base / m / "_summary.json").read_text())["results"] for m in METHODS}
    _ids = {m: {r["id"] for r in _summ[m] if r.get("status") == "ok"} for m in METHODS}
    _paired = sorted(set.intersection(*_ids.values()))
    for m in PER_ITER_METHODS:  # all methods now emit per-iter bug_found (incl. FF)
        for cid in _paired:
            p = iter_path(_ds, m, cid)
            if not p.exists():
                continue
            for it in json.loads(p.read_text()).get("iterations", []):
                calls = it.get("fuzz_input", {}).get("calls", [])
                if not isinstance(calls, list) or not calls:
                    continue
                depth = len(calls)
                width = len({str(c[0]) for c in calls if isinstance(c, list) and c})
                fo = it.get("fuzzing_output", {})
                bug = bool(fo.get("bug_found")) if isinstance(fo, dict) else False
                di = next((i for i, (lo, hi, _) in enumerate(DEPTH_BINS) if lo <= depth <= hi), None)
                wi = next((i for i, (lo, hi, _) in enumerate(WIDTH_BINS) if lo <= width <= hi), None)
                if di is None or wi is None:
                    continue
                dw_tot[di, wi] += 1
                dw_bug[di, wi] += 1 if bug else 0
dw_rate = np.divide(dw_bug, np.where(dw_tot == 0, 1, dw_tot)) * 100
_dlab = [b[2] for b in DEPTH_BINS]; _wlab = [b[2] for b in WIDTH_BINS]
rate_df = pd.DataFrame(dw_rate, index=_dlab, columns=_wlab)
cnt_df = pd.DataFrame(dw_tot.astype(int), index=_dlab, columns=_wlab)
rate_df.to_csv(OUT / "10_depthwidth_bugrate.csv")
cnt_df.to_csv(OUT / "10b_depthwidth_counts.csv")
dw_annot = [[f"{dw_rate[i, j]:.1f}%\n(n={int(dw_tot[i, j])})" if dw_tot[i, j] else "—"
             for j in range(len(_wlab))] for i in range(len(_dlab))]
plt.figure(figsize=(8.5, 6))
sns.heatmap(rate_df, annot=dw_annot, fmt="", cmap="rocket_r", linewidths=.5, linecolor="white",
            vmin=0, cbar_kws={"label": "bug-rate (%)"})
plt.xlabel("sequence width  (# distinct functions called)")
plt.ylabel("sequence depth  (# calls)")
plt.title(f"What test-case shape finds bugs — {DS} (N={N})\nbug-rate by depth × width, pooled over methods")
plt.tight_layout(); plt.savefig(OUT / "B10_depthwidth_bugrate.png", dpi=150, bbox_inches="tight"); plt.close()
print("\n=== DEPTH×WIDTH BUG-RATE % (rows=depth, cols=width) ===\n", rate_df.round(1).to_string())

# =============================================================================
#  EDA: static features -> outcomes (eda_survey §15.7, restricted to paired set)
# =============================================================================
sys.path.insert(0, str(ROOT / "src" / "experiment" / "eda"))
from dataframe import build_dataframe  # noqa
fdf = build_dataframe()
fdf = fdf[fdf.dataset.isin(DATASETS)].copy()
# align contract key with df ('contract' = last path segment / file stem)
fdf["contract"] = fdf["contract_id"].apply(lambda c: c.split("/")[-1].replace(".sol", ""))
# difficulty: how many of 5 methods solved it; mean coverage across methods
out_cols = {f"{m}__bc_cov": m for m in METHODS}
solved = fdf[[f"{m}__bug_found_any" for m in METHODS]].sum(axis=1)
fdf["n_methods_solved"] = solved
fdf["mean_cov_all"] = fdf[[f"{m}__bc_cov" for m in METHODS]].mean(axis=1)
fdf["any_solved"] = (solved > 0).astype(int)
META = {"dataset","contract_id","category","name","chain","src_loc_path","contract",
        "n_methods_solved","mean_cov_all","any_solved"}
FEATS = [c for c in fdf.columns if "__" not in c and c not in META]
# keep paired contracts only, numeric features with variance
eda = fdf[fdf[[f"{m}__result_available" for m in METHODS]].all(axis=1)].copy()
print(f"\n[EDA] feature rows (paired & all-methods): {len(eda)}")
num_feats = [f for f in FEATS if pd.api.types.is_numeric_dtype(eda[f]) and eda[f].nunique() > 2]

def spearman_tab(target):
    out = []
    for f in num_feats:
        rho, p = stats.spearmanr(eda[f], eda[target])
        if not math.isnan(rho):
            out.append((f, rho, p))
    return pd.DataFrame(out, columns=["feature", "rho", "p"]).set_index("feature").sort_values("rho")

cov_corr = spearman_tab("mean_cov_all")
diff_corr = spearman_tab("n_methods_solved")
cov_corr.to_csv(OUT / "E1_feature_vs_coverage_spearman.csv")
diff_corr.to_csv(OUT / "E2_feature_vs_solvability_spearman.csv")
print("\n=== EDA top |rho| feature vs mean coverage ===\n",
      cov_corr.reindex(cov_corr.rho.abs().sort_values(ascending=False).index).head(8).round(3).to_string())
print("\n=== EDA top |rho| feature vs #methods-solved ===\n",
      diff_corr.reindex(diff_corr.rho.abs().sort_values(ascending=False).index).head(8).round(3).to_string())

def corr_bar(tab, title, fname):
    t = tab.reindex(tab.rho.abs().sort_values(ascending=False).index).head(12).sort_values("rho")
    plt.figure(figsize=(10, 7))
    cols = ["#2e7d32" if v > 0 else "#c62828" for v in t.rho]
    plt.barh(t.index, t.rho, color=cols)
    plt.axvline(0, color="k", lw=.8); plt.xlabel("Spearman ρ"); plt.title(title)
    plt.tight_layout(); plt.savefig(OUT / fname, dpi=150, bbox_inches="tight"); plt.close()
corr_bar(cov_corr, f"Static feature ↔ mean coverage ({DS}, N={len(eda)})", "C1_feature_vs_coverage.png")
corr_bar(diff_corr, f"Static feature ↔ # methods that solve ({DS}, N={len(eda)})", "C2_feature_vs_solvability.png")

# feature correlation heatmap (top discriminative features)
top = list(dict.fromkeys(list(cov_corr.reindex(cov_corr.rho.abs().sort_values(ascending=False).index).head(8).index)
                         + list(diff_corr.reindex(diff_corr.rho.abs().sort_values(ascending=False).index).head(8).index)))
plt.figure(figsize=(10, 8))
sns.heatmap(eda[top].corr(method="spearman"), annot=True, fmt=".2f", cmap="RdBu_r", center=0,
            square=True, cbar_kws={"shrink": .7}, annot_kws={"size": 8})
plt.title(f"Feature–feature Spearman ({DS})"); plt.tight_layout()
plt.savefig(OUT / "A3_feature_corr.png", dpi=150, bbox_inches="tight"); plt.close()

# =============================================================================
#  EDA: breadth × depth quadrants (eda_survey §9 method, on the PAIRED set)
#  BUGFIX: notebook §9 split the FULL unpaired corpus (defihacklabs 63 /
#  smartbugs 116) → quadrant n's (e.g. SB wide+deep n=27) were inconsistent
#  with the paired N=25/17 used everywhere else. Same method, paired data,
#  within-dataset median split → quadrant n's now sum to the paired N.
# =============================================================================
BREADTH, DEPTH = "total_fn_count", "max_branches_per_fn"
quad_rows, fisher_rows, seqdiv_rows = [], [], []
for ds_name, sub in eda.groupby("dataset"):
    if len(sub) < 8:
        print(f"[breadth×depth] {ds_name}: paired N={len(sub)} < 8 — skipped"); continue
    b_med, d_med = sub[BREADTH].median(), sub[DEPTH].median()
    sub = sub.assign(breadth_bin=np.where(sub[BREADTH] > b_med, "wide", "narrow"),
                     depth_bin=np.where(sub[DEPTH] > d_med, "deep", "shallow"))
    for (bb, db), cell in sub.groupby(["breadth_bin", "depth_bin"]):
        row = dict(dataset=ds_name, quadrant=f"{bb}+{db}", n=len(cell))
        for m in METHODS:
            row[f"{m}_cov"] = round(float(cell[f"{m}__bc_cov"].mean()), 3)
            row[f"{m}_bugrate"] = round(float(cell[f"{m}__bug_found_any"].mean()), 3)
        covm = {m: cell[f"{m}__bc_cov"].mean() for m in METHODS}
        row["cov_winner"] = LABELS[max(covm, key=covm.get)]
        quad_rows.append(row)
    is_deep = sub[DEPTH] > d_med
    for m in METHODS:
        pos = sub[f"{m}__bug_found_any"].astype(bool)
        a = int((is_deep & pos).sum()); b = int((is_deep & ~pos).sum())
        c = int((~is_deep & pos).sum()); d = int((~is_deep & ~pos).sum())
        try: orr, p = stats.fisher_exact([[a, b], [c, d]])
        except ValueError: orr, p = float("nan"), float("nan")
        fisher_rows.append(dict(dataset=ds_name, method=LABELS[m],
            deep_bugrate=round(a/max(1, a+b), 3), shallow_bugrate=round(c/max(1, c+d), 3),
            n_deep=a+b, n_shallow=c+d, odds_ratio=round(orr, 2), p_value=round(p, 3)))
    for m in METHODS:
        s = sub[f"{m}__sequence_diversity"].dropna()
        seqdiv_rows.append(dict(dataset=ds_name, method=LABELS[m],
            mean_seq_div=round(float(s.mean()), 3) if len(s) else float("nan"),
            std_seq_div=round(float(s.std()), 3) if len(s) else float("nan")))
quad_df = pd.DataFrame(quad_rows); fisher_df2 = pd.DataFrame(fisher_rows); seqdiv_df = pd.DataFrame(seqdiv_rows)
quad_df.to_csv(OUT / "E4_breadth_depth_quadrants.csv", index=False)
fisher_df2.to_csv(OUT / "E5_depth_fisher.csv", index=False)
seqdiv_df.to_csv(OUT / "E6_sequence_diversity.csv", index=False)
print("\n=== BREADTH×DEPTH quadrants (paired) ===\n", quad_df.to_string(index=False))
print("\n=== DEPTH fisher deep-vs-shallow (paired) ===\n", fisher_df2.to_string(index=False))
print("\n=== SEQUENCE diversity (paired) ===\n", seqdiv_df.to_string(index=False))

if len(quad_df):
    nds = quad_df["dataset"].nunique()
    fig, axes = plt.subplots(1, nds + 1, figsize=(7*(nds+1), 6), squeeze=False); axes = axes[0]
    for ax, (ds_name, q) in zip(axes, quad_df.groupby("dataset")):
        q = q.set_index("quadrant")
        q[[f"{m}_cov" for m in METHODS]].plot(kind="bar", ax=ax, legend=False,
                                              color=[PALETTE[m] for m in METHODS])
        ax.set_title(f"{ds_name}: mean bc_cov by quadrant (paired)")
        ax.set_ylabel("mean bc_cov"); ax.set_xlabel(""); ax.tick_params(axis="x", rotation=20)
        for i, (_, r) in enumerate(q.iterrows()):
            ax.annotate(f"n={int(r['n'])}", (i, 0.005), ha="center", fontsize=9)
    axS = axes[-1]
    sd_piv = seqdiv_df.pivot(index="method", columns="dataset", values="mean_seq_div").reindex(
        [LABELS[m] for m in METHODS])
    sd_piv.plot(kind="bar", ax=axS, width=0.8, edgecolor="white")
    axS.set_title("Sequence diversity by dataset (exploration breadth)")
    axS.set_ylabel("mean Jaccard dist between consecutive calls"); axS.set_xlabel("")
    axS.tick_params(axis="x", rotation=20); axS.legend(title="", fontsize=9)
    fig.legend([LABELS[m] for m in METHODS], loc="upper center", ncol=5, fontsize=10)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(OUT / "C3_breadth_depth.png", dpi=150, bbox_inches="tight"); plt.close()

# =============================================================================
#  C4: generation difficulty (PoC-derived) ↔ solvability.  Difficulty (DIFF /
#  diff_level / diff_bits) is computed once near the top (method-independent,
#  self-information from enrich.json poc.calls); here it is crossed with detection.
# =============================================================================
det_by = df.assign(level=df["contract"].map(lambda k: (DIFF.get(k) or ("EASY", 0.0, False))[0]),
                   bits =df["contract"].map(lambda k: (DIFF.get(k) or ("EASY", 0.0, False))[1]))
present = [l for l in LEVELS if (det_by["level"] == l).any()]
# method x level detection-rate matrix (+ k/n annotation)
rate = pd.DataFrame(index=[LABELS[m] for m in METHODS], columns=present, dtype=float)
annot = pd.DataFrame(index=[LABELS[m] for m in METHODS], columns=present, dtype=object)
c4_rows = []
for m in METHODS:
    g = det_by[det_by.method == m]
    # Spearman detection vs continuous self-information (monotone check)
    r_sp = (stats.spearmanr(g["found"].astype(int), g["bits"])[0]
            if g["found"].nunique() > 1 else float("nan"))
    for l in present:
        cell = g[g.level == l]; k = int(cell["found"].sum()); n = len(cell)
        rate.loc[LABELS[m], l] = k / n if n else np.nan
        annot.loc[LABELS[m], l] = f"{k/n:.2f}\n{k}/{n}" if n else "—"
    c4_rows.append(dict(method=LABELS[m],
                        **{f"{l}_rate": round(float(rate.loc[LABELS[m], l]), 3) if not pd.isna(rate.loc[LABELS[m], l]) else np.nan for l in present},
                        corr_det_bits=round(float(r_sp), 3)))
c4_df = pd.DataFrame(c4_rows)
pop = {l: int((det_by.drop_duplicates("contract")["level"] == l).sum()) for l in present}
c4_df.to_csv(OUT / "C4_gen_difficulty.csv", index=False)
print("\n=== C4 generation-difficulty × detection (level pop: "
      + " ".join(f"{l}={pop[l]}" for l in present) + ") ===\n", c4_df.to_string(index=False))

plt.figure(figsize=(1.6*len(present)+4, 0.7*len(METHODS)+2))
sns.heatmap(rate.astype(float), annot=annot.values, fmt="", cmap="Greens", vmin=0, vmax=1,
            linewidths=.5, linecolor="white", cbar_kws={"label": "detection rate"})
plt.title(f"Detection rate by method × PoC-difficulty level ({DS}, N={N})\n"
          + " · ".join(f"{l} n={pop[l]}" for l in present), fontsize=11)
plt.xlabel("PoC generation-difficulty level  (harder →)"); plt.ylabel("")
plt.tight_layout(); plt.savefig(OUT / "C4_gen_difficulty.png", dpi=150, bbox_inches="tight"); plt.close()

blob = dict(ds=DS, N=N, eda_N=len(eda), union_solvable=union_solv, best_base=LABELS[best_base],
            h2h_win=win, h2h_tie=tie, auc={LABELS[m]: auc[m] for m in PER_ITER_METHODS},
            summary=summary.reset_index().to_dict("records"),
            stats=stats_df.reset_index().to_dict("records"),
            comp=comp_df.reset_index().to_dict("records"),
            cov_corr=cov_corr.reset_index().to_dict("records"),
            diff_corr=diff_corr.reset_index().to_dict("records"))
(OUT / "_report_blob.json").write_text(json.dumps(blob, indent=1, default=float))
print("\nWritten ->", OUT)
