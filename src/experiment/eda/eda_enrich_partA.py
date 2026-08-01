"""Regenerate Part A (dataset EDA) figures/stats on the ENRICHED (runnable) set only.

Why: the experiment is run on the runnable enrich rows (33 SmartBugs / 25 DeFiHackLabs),
but the eda_survey notebook builds Part A over load_all (116 / 63 incl. skipped). This
re-emits A2 feature stats + A3 spearman heatmaps over the enriched subset, and adds a
vuln-type distribution (A1) over the same subset.

Outputs (research/figures/):
  01_feature_stats_by_dataset_enrich.csv   A2 table source (enriched)
  02_spearman_heatmap_<ds>.png             A3 heatmaps (enriched, overwritten)
  A1_vuln_distribution.csv / .png         A1 vuln-type distribution (enriched)
"""
from __future__ import annotations
import sys, collections
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src" / "experiment" / "eda"))
sys.path.insert(0, str(ROOT / "src" / "experiment" / "dataloader"))
from dataframe import build_dataframe  # noqa
from schema import load_dataset  # noqa

sns.set_theme(style="whitegrid", context="notebook")
FIG = ROOT / "research" / "figures"
FIG.mkdir(parents=True, exist_ok=True)

FEATURE_COLS = ['loc', 'cyclomatic_complexity', 'inheritance_depth',
                'external_fn_count', 'total_fn_count', 'payable_fn_count',
                'max_branches_per_fn', 'avg_branches_per_fn', 'branch_gini',
                'library_use_count',
                'defi_action_count_total', 'has_oracle', 'has_uniswap',
                'has_flashloan', 'access_control_modifier_uses',
                'uncontrolled_token_op_count',
                'hardcoded_address_count', 'magic_number_count',
                'uses_timestamp', 'uses_blocknum', 'has_reentrancy_guard',
                'require_count', 'constraint_density']

df = build_dataframe()
run_ids = {ds: set(c.id for c in load_dataset(ds).contracts)
           for ds in ("smartbugs", "defihacklabs")}
enr = df[df.apply(lambda r: r.contract_id in run_ids[r.dataset], axis=1)].copy()
print("enriched rows:", enr['dataset'].value_counts().to_dict())

# ── A2: feature stats on enriched ────────────────────────────────────────────
summary = enr.groupby('dataset')[FEATURE_COLS].agg(['median', 'mean']).round(2)
summary.columns = ['_'.join(c) for c in summary.columns]
summary.to_csv(FIG / '01_feature_stats_by_dataset_enrich.csv')
print("\n=== A2 enriched feature stats (median / mean) ===")
for f in ['loc', 'cyclomatic_complexity', 'total_fn_count', 'external_fn_count',
          'max_branches_per_fn', 'defi_action_count_total', 'require_count',
          'inheritance_depth', 'has_uniswap', 'constraint_density']:
    d = enr[enr.dataset == 'defihacklabs'][f]
    s = enr[enr.dataset == 'smartbugs'][f]
    ratio = (d.median() / s.median()) if s.median() else float('nan')
    print(f"{f:28s} DeFi {d.median():8.2f}({d.mean():7.2f})  SB {s.median():7.2f}({s.mean():6.2f})  ratio {ratio:.1f}")

# ── A3: spearman heatmaps on enriched ────────────────────────────────────────
for ds, sub in enr.groupby('dataset'):
    corr = sub[FEATURE_COLS].rank().corr(method='spearman')
    fig, ax = plt.subplots(figsize=(11, 9))
    sns.heatmap(corr, cmap='RdBu_r', center=0, vmin=-1, vmax=1, square=True,
                cbar_kws={'label': 'Spearman ρ'}, annot=False, ax=ax)
    ax.set_title(f'Feature collinearity — {ds} (enriched/runnable, N={len(sub)})')
    plt.tight_layout()
    fig.savefig(FIG / f'02_spearman_heatmap_{ds}.png', dpi=140)
    plt.close(fig)
    print(f"wrote 02_spearman_heatmap_{ds}.png (N={len(sub)})")

# ── A1: vuln-type distribution on enriched ───────────────────────────────────
dist = (enr.groupby(['dataset', 'category']).size()
        .rename('n').reset_index().sort_values(['dataset', 'n'], ascending=[True, False]))
dist.to_csv(FIG / 'A1_vuln_distribution.csv', index=False)
print("\n=== A1 vuln-type distribution (enriched) ===")
print(dist.to_string(index=False))

def _plot_vuln(ax, ds):
    d = dist[dist.dataset == ds].sort_values('n', ascending=True)
    ax.barh(d['category'], d['n'], color='#4C72B0')
    for y, (cat, n) in enumerate(zip(d['category'], d['n'])):
        ax.text(n + 0.1, y, str(int(n)), va='center', fontsize=10)
    ax.set_title(f"{ds} (N={int(d['n'].sum())})")
    ax.set_xlabel('# contracts')

# two-panel (combined / pooled reports)
fig, axes = plt.subplots(1, 2, figsize=(13, 4.5))
for ax, ds in zip(axes, ['defihacklabs', 'smartbugs']):
    _plot_vuln(ax, ds)
fig.suptitle('Vulnerability-class distribution — enriched/runnable set', y=1.02)
plt.tight_layout()
fig.savefig(FIG / 'A1_vuln_distribution.png', dpi=140, bbox_inches='tight')
plt.close(fig)
print("wrote A1_vuln_distribution.png")

# per-dataset standalone (single-dataset reports)
for ds in ['defihacklabs', 'smartbugs']:
    fig, ax = plt.subplots(figsize=(6.5, 4))
    _plot_vuln(ax, ds)
    ax.set_title(f'Vulnerability-class distribution — {ds} (enriched/runnable, '
                 f"N={int(dist[dist.dataset == ds]['n'].sum())})")
    plt.tight_layout()
    fig.savefig(FIG / f'A1_vuln_distribution_{ds}.png', dpi=140, bbox_inches='tight')
    plt.close(fig)
    print(f"wrote A1_vuln_distribution_{ds}.png")
