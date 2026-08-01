# Experiment Analysis — Combined (DeFiHackLabs vs SmartBugs)

*Line-by-line comparison of the two datasets. Tables show both corpora side-by-side; figures are the
per-dataset figures placed next to each other (left = DeFiHackLabs, right = SmartBugs).*

> **Reading guide.** This file is **results only** — every section is a table or a pair of figures with a
> short *how-to-read* caption (axes + what "good" looks like). No interpretation/claims here; those live in
> `research/research.md` and the paper. Single-dataset detail:
> [defihacklabs](experiment_analysis_defihacklabs.md) · [smartbugs](experiment_analysis_smartbugs.md) ·
> [pooled](experiment_analysis_pooled.md) (both as one corpus).
>
> **Scope.** DeFiHackLabs N=25, SmartBugs N=33, 100 iters/contract, 6 methods (5 in-house + FinanceFuzz).
> The 3 LLM-driven methods (MADFuzz / LLMFuzz / SSCFuzz) are additionally swept over three backend sizes
> (1.5B / 3B / 7B of one model family) across Part B's method-comparison views (B1–B8 — each backend size shown as its own bar / line / box / column / table row); the SSCFuzz-internal sections (B9, B10) and Parts C–E stay on the 1.5B backend.

<!-- TOC -->
## Contents

- [Part A · Dataset EDA](#part-a--dataset-eda)
  - [A1. Vulnerability-class distribution](#a1-vulnerability-class-distribution)
  - [A2. Static feature profile — median (mean) per corpus](#a2-static-feature-profile--median-mean-per-corpus)
  - [A3. Feature collinearity](#a3-feature-collinearity)
  - [A4. Sample difficulty distribution](#a4-sample-difficulty-distribution)
- [Part B · Method results](#part-b--method-results)
  - [B1. Detection & coverage](#b1-detection--coverage)
  - [B2. Coverage growth](#b2-coverage-growth)
  - [B3. Coverage distribution](#b3-coverage-distribution)
  - [B4. Time-to-first-bug](#b4-time-to-first-bug)
  - [B5. SSCFuzz vs each baseline (paired, Δcov / Cliff's δ / Wilcoxon p)](#b5-sscfuzz-vs-each-baseline-paired-δcov--cliffs-δ--wilcoxon-p)
  - [B6. Complementarity & head-to-head](#b6-complementarity--head-to-head)
  - [B7. Cost efficiency](#b7-cost-efficiency)
  - [B8. Detection by vulnerability class](#b8-detection-by-vulnerability-class)
  - [B9. Action selection](#b9-action-selection)
  - [B10. Sequence depth × width](#b10-sequence-depth--width)
- [Part C · Feature ↔ outcome](#part-c--feature--outcome)
  - [C1. Feature ↔ coverage](#c1-feature--coverage)
  - [C2. Feature ↔ solvability](#c2-feature--solvability)
  - [C3. Breadth × depth](#c3-breadth--depth)
  - [C4. Generation difficulty (PoC-derived) ↔ solvability](#c4-generation-difficulty-poc-derived--solvability)
- [Part D · SSCFuzz internals](#part-d--sscfuzz-internals)
  - [D1. Per-strategy search yield](#d1-per-strategy-search-yield)
  - [D2. Strategy × vulnerability class (genuine)](#d2-strategy--vulnerability-class-genuine)
  - [D3. Mutation: genuine vs inherited](#d3-mutation-genuine-vs-inherited)
  - [D4. Selection vs yield](#d4-selection-vs-yield)
  - [D5. RL-greedy vs ε-random](#d5-rl-greedy-vs-ε-random)
  - [D6. Strategy selection over iterations](#d6-strategy-selection-over-iterations)
- [Part E · Oracle precision](#part-e--oracle-precision)
  - [E1. FinanceFuzz — detected property vs planted class](#e1-financefuzz--detected-property-vs-planted-class)
  - [E2. Detection & union under strict scoring](#e2-detection--union-under-strict-scoring)
  - [E3. In-house signal caveat — PLN](#e3-in-house-signal-caveat--pln)
  - [Caveats & reproduction](#caveats--reproduction)

<!-- /TOC -->

# Part A · Dataset EDA

*Static contract structure — no fuzzing results, so identical across LLM backend sizes; the backend comparison lives in Part B's method-comparison figures + the B1 / B5 tables.*

## A1. Vulnerability-class distribution

![DeFiHackLabs](../figures/A1_vuln_distribution_defihacklabs.png)
![SmartBugs](../figures/A1_vuln_distribution_smartbugs.png)

| DeFiHackLabs (N=25) | n | | SmartBugs (N=33) | n |
|---|---|---|---|---|
| access_control | 9 | | reentrancy | 18 |
| arbitrary_mint | 7 | | access_control | 11 |
| business_logic | 6 | | arithmetic | 3 |
| price_oracle_manipulation | 3 | | unchecked_low_level_calls | 1 |

*How to read:* labelled vuln class per contract (per-class denominator for B8). The two corpora are
class-imbalanced in opposite ways.

## A2. Static feature profile — median (mean) per corpus

| feature | DeFiHackLabs | SmartBugs | ratio (median) |
|---|---|---|---|
| `loc` | 477 (554) | 26 (48) | ~18× |
| `cyclomatic_complexity` | 47 (52) | 4 (5.9) | ~12× |
| `total_fn_count` | 57 (61) | 4 (4.9) | ~14× |
| `external_fn_count` | 14 (16) | 4 (4.2) | ~3.5× |
| `max_branches_per_fn` | 11 (16) | 2 (3.2) | ~5.5× |
| `defi_action_count_total` | 22 (23) | 2 (1.9) | ~11× |
| `require_count` | 24 (23) | 1 (1.3) | ~24× |
| `constraint_density` | 0.05 (0.05) | 0.02 (0.04) | ~2.5× |

*How to read:* median (mean) per corpus; ratio = how many × larger DeFiHackLabs is on that feature.

## A3. Feature collinearity

![DeFiHackLabs](../figures/experiment/A3_feature_corr.png)
![SmartBugs](../figures/experiment_smartbugs/A3_feature_corr.png)

*How to read:* Spearman ρ between every pair of static features per corpus; darker = more correlated.

## A4. Sample difficulty distribution

![DeFiHackLabs](../figures/experiment/A4_gen_difficulty_dist.png)
![SmartBugs](../figures/experiment_smartbugs/A4_gen_difficulty_dist.png)

*How to read:* one bar per contract (left = DeFiHackLabs, right = SmartBugs); **bar height =
self-information `H = log₂(RandomFuzz search-space size) = −log₂ P`**, the probability the blind RandomFuzz baseline draws a satisfying input in one try (expected random draws ≈ 2^H) — from the ground-truth PoC, no
fuzzer run. Each call adds `log₂(F)` (F = `external_fn_count`); each constrained argument adds `log₂(pool)`
with the pool RandomFuzz's draw set (address corpus = declared externals + `hardcoded_address_count`; constant
pool = `magic_number_count`); a coordinate RandomFuzz CANNOT draw takes the full type domain (2²⁵⁶ / 2¹⁶⁰): a runtime-derived `$ret` value, a specific on-chain address not in the seeded corpus, or a numeric literal outside RandomFuzz's boundary/scale pool (a keccak storage slot or an arbitrary large amount); a burn/zero address (`0x…dEaD` / `0x0`) is an arbitrary recipient → free.
**Color = difficulty level:** EASY · NORMAL · HIGH = data-driven tertiles of H over the RandomFuzz-reachable contracts (dotted
lines = tertile edges, shared by both corpora); IMPOSSIBLE = needs a RandomFuzz-unreachable coordinate, bars capped.
Per-level counts: DeFiHackLabs E4·N2·H3·I16; SmartBugs E9·N10·H10·I4.

# Part B · Method results

## B1. Detection & coverage

*DeFiHackLabs (N=25)* — det = fraction with ≥1 bug, cov = bytecode-branch coverage; three sub-columns
per metric = LLM backend size (1.5B / 3B / 7B).

| method | det 1.5B | det 3B | det 7B | cov 1.5B | cov 3B | cov 7B |
|---|---|---|---|---|---|---|
| RandomFuzz | 8 % | 8 % | 8 % | 0.488 | 0.488 | 0.488 |
| FinanceFuzz | 4 % | 4 % | 4 % | 0.179 | 0.179 | 0.179 |
| RLFuzz | 40 % | 40 % | 40 % | 0.545 | 0.545 | 0.545 |
| MADFuzz | 40 % | 28 % | — | 0.515 | 0.509 | — |
| LLMFuzz | 24 % | 28 % | 36 % | 0.343 | 0.374 | 0.361 |
| SSCFuzz (ours) | 40 % | 48 % | 48 % | 0.487 | 0.486 | 0.481 |

*SmartBugs (N=33)*

| method | det 1.5B | det 3B | det 7B | cov 1.5B | cov 3B | cov 7B |
|---|---|---|---|---|---|---|
| RandomFuzz | 33 % | 33 % | 33 % | 0.643 | 0.643 | 0.643 |
| FinanceFuzz | 18 % | 18 % | 18 % | 0.566 | 0.566 | 0.566 |
| RLFuzz | 39 % | 39 % | 39 % | 0.729 | 0.729 | 0.729 |
| MADFuzz | 33 % | 39 % | — | 0.697 | 0.691 | — |
| LLMFuzz | 36 % | 48 % | 48 % | 0.643 | 0.690 | 0.682 |
| SSCFuzz (ours) | 39 % | 48 % | 45 % | 0.716 | 0.727 | 0.730 |

![DeFiHackLabs](../figures/experiment/B1_detection_coverage_by_model.png)
![SmartBugs](../figures/experiment_smartbugs/B1_detection_coverage_by_model.png)

*How to read:* det = fraction of the paired contracts with ≥1 bug; cov = mean bytecode-branch coverage. The
three sub-columns per metric are the LLM backend size — 1.5B / 3B / 7B of one model family. RandomFuzz /
FinanceFuzz / RLFuzz do not call the LLM, so their size columns repeat one run. `—` = that size's run is not
available for this set (absent, partial, or unfinished). **Figures:** one bar per method × backend size
(left = DeFiHackLabs, right = SmartBugs) — coloured by method, darker = bigger backend; LLM-free methods
appear once, and a size with no complete run has no bar. (FinanceFuzz detection validity → Part E.)

## B2. Coverage growth

![DeFiHackLabs](../figures/experiment/B2_coverage_growth_by_model.png)
![SmartBugs](../figures/experiment_smartbugs/B2_coverage_growth_by_model.png)

*How to read:* x = iteration, y = cumulative mean coverage; higher and still-rising = better. Each LLM-driven method is one line per backend size (1.5B / 3B / 7B; darker = bigger); RandomFuzz / FinanceFuzz / RLFuzz appear once.

## B3. Coverage distribution

![DeFiHackLabs](../figures/experiment/B3_coverage_box_by_model.png)
![SmartBugs](../figures/experiment_smartbugs/B3_coverage_box_by_model.png)

*How to read:* higher median + tighter spread = better. One box per (method × backend size) — LLM-driven methods get a box per size (1.5B / 3B / 7B, darker = bigger), LLM-free once.

## B4. Time-to-first-bug

![DeFiHackLabs](../figures/experiment/B4_time_to_bug_by_model.png)
![SmartBugs](../figures/experiment_smartbugs/B4_time_to_bug_by_model.png)

*How to read:* Kaplan–Meier — y = fraction still without a bug at iteration x; dropping early and low = better. One line per (method × backend size), darker = bigger backend; LLM-free methods appear once.

## B5. SSCFuzz vs each baseline (paired, Δcov / Cliff's δ / Wilcoxon p)

| baseline (method × backend size) | DeFiHackLabs | SmartBugs |
|---|---|---|
| RandomFuzz | −0.001 / +0.02 / 0.958 | +0.073 / +0.54 / <0.001 |
| FinanceFuzz | +0.307 / +0.88 / <0.001 | +0.150 / +0.79 / <0.001 |
| RLFuzz | −0.059 / −0.26 / <0.001 | −0.013 / −0.07 / 0.093 |
| MADFuzz·1.5B | −0.029 / −0.13 / 0.015 | +0.019 / +0.05 / 0.132 |
| MADFuzz·3B | −0.022 / −0.09 / 0.086 | +0.025 / +0.16 / 0.056 |
| LLMFuzz·1.5B | +0.144 / +0.53 / <0.001 | +0.073 / +0.50 / 0.0002 |
| LLMFuzz·3B | +0.113 / +0.47 / <0.001 | +0.026 / +0.24 / 0.055 |
| LLMFuzz·7B | +0.126 / +0.48 / <0.001 | +0.034 / +0.33 / 0.005 |
| SSCFuzz·3B | +0.000 / +0.01 / 0.976 | −0.011 / −0.07 / 0.388 |
| SSCFuzz·7B | +0.006 / +0.04 / 0.465 | −0.014 / −0.09 / 0.239 |

*How to read:* reference = **SSCFuzz·1.5B (ours)**; cell = Δcov / Cliff's δ / Wilcoxon p, Δcov = ours − the
row's (method × backend size) per corpus (positive = ours covers more); SSCFuzz·3B/·7B rows compare bigger
backends of our own method against 1.5B. |δ|>0.47 = large; p<0.05 = significant.

## B6. Complementarity & head-to-head

![DeFiHackLabs](../figures/experiment/B6_detection_heatmap_by_model.png)
![SmartBugs](../figures/experiment_smartbugs/B6_detection_heatmap_by_model.png)

| | DeFiHackLabs | SmartBugs |
|---|---|---|
| union over all method × backend size (any-signal) | 16/25 | 22/33 |

*How to read:* heatmap = which (method × backend size) (column, left = DeFiHackLabs / right = SmartBugs) solves
which contract (row); green = ≥1 bug. Rows are sorted hardest→easiest by PoC difficulty (A4), each contract
prefixed with its level initial (`E`=EASY / `N`=NORMAL / `H`=HIGH / `I`=IMPOSSIBLE). union = contracts solved
by ≥1 (method × size) (any-signal; strict scoring → E2).

## B7. Cost efficiency

![DeFiHackLabs](../figures/experiment/B7_cost_efficiency_by_model.png)
![SmartBugs](../figures/experiment_smartbugs/B7_cost_efficiency_by_model.png)

*How to read:* bugs per 1k LLM tokens (Random/RL token-free); higher = cheaper per bug. One bar per (method × backend size), darker = bigger; token-free methods (Random/RL) are omitted.

## B8. Detection by vulnerability class

![DeFiHackLabs](../figures/experiment/B8_category_detection_by_model.png)
![SmartBugs](../figures/experiment_smartbugs/B8_category_detection_by_model.png)

*How to read:* rows = vulnerability class, columns = each (method × backend size); cell = detection rate on that class (k-with-bug / class n), greener = higher. LLM-driven methods span 1.5B / 3B / 7B (left→right), LLM-free (Random/Finance/RL) appear once; a size with no complete run is omitted. (Classes differ by corpus; FinanceFuzz credit is by reported signal → Part E.)

## B9. Action selection

![DeFiHackLabs](../figures/experiment/B9_selection_heatmap.png)
![SmartBugs](../figures/experiment_smartbugs/B9_selection_heatmap.png)

*How to read:* fraction of a method's iterations spent on each strategy / group / mutation (RandomFuzz
excluded). Flat = broad exploration; concentrated = narrow policy.

## B10. Sequence depth × width

![DeFiHackLabs](../figures/experiment/B10_depthwidth_bugrate.png)
![SmartBugs](../figures/experiment_smartbugs/B10_depthwidth_bugrate.png)

*How to read:* depth = #calls, width = #distinct functions; cell = bug-rate of that shape. Hotter = more
likely to trigger a bug.

# Part C · Feature ↔ outcome

## C1. Feature ↔ coverage

![DeFiHackLabs](../figures/experiment/C1_feature_vs_coverage.png)
![SmartBugs](../figures/experiment_smartbugs/C1_feature_vs_coverage.png)

*How to read:* ρ between each feature and mean coverage; negative = harder to cover.

## C2. Feature ↔ solvability

![DeFiHackLabs](../figures/experiment/C2_feature_vs_solvability.png)
![SmartBugs](../figures/experiment_smartbugs/C2_feature_vs_solvability.png)

*How to read:* solvability = how many of the 6 methods find a bug; ρ vs each feature (negative = harder).

## C3. Breadth × depth

![DeFiHackLabs](../figures/experiment/C3_breadth_depth.png)
![SmartBugs](../figures/experiment_smartbugs/C3_breadth_depth.png)

*How to read:* contracts split at the within-dataset median breadth × depth → 4 quadrants; cell = the
coverage-winning method per quadrant.

## C4. Generation difficulty (PoC-derived) ↔ solvability

![DeFiHackLabs](../figures/experiment/C4_gen_difficulty.png)
![SmartBugs](../figures/experiment_smartbugs/C4_gen_difficulty.png)

| method | DeFi E (4) | DeFi N (2) | DeFi H (3) | DeFi I (16) | SB E (9) | SB N (10) | SB H (10) | SB I (4) |
|---|---|---|---|---|---|---|---|---|
| RandomFuzz | 0.50 (2/4) | 0.00 (0/2) | 0.00 (0/3) | 0.00 (0/16) | 0.78 (7/9) | 0.30 (3/10) | 0.10 (1/10) | 0.00 (0/4) |
| FinanceFuzz | 0.25 (1/4) | 0.00 (0/2) | 0.00 (0/3) | 0.00 (0/16) | 0.11 (1/9) | 0.20 (2/10) | 0.30 (3/10) | 0.00 (0/4) |
| RLFuzz | 1.00 (4/4) | 0.50 (1/2) | 0.33 (1/3) | 0.25 (4/16) | 1.00 (9/9) | 0.20 (2/10) | 0.20 (2/10) | 0.00 (0/4) |
| MADFuzz | 1.00 (4/4) | 1.00 (2/2) | 0.00 (0/3) | 0.25 (4/16) | 1.00 (9/9) | 0.20 (2/10) | 0.00 (0/10) | 0.00 (0/4) |
| LLMFuzz | 0.75 (3/4) | 0.00 (0/2) | 0.00 (0/3) | 0.19 (3/16) | 0.89 (8/9) | 0.40 (4/10) | 0.00 (0/10) | 0.00 (0/4) |
| SSCFuzz (ours) | 1.00 (4/4) | 0.50 (1/2) | 0.00 (0/3) | 0.31 (5/16) | 1.00 (9/9) | 0.20 (2/10) | 0.10 (1/10) | 0.25 (1/4) |

*How to read:* difficulty **level** = RandomFuzz reachability, scored from the ground-truth PoC (defined in
[A4](#a4-sample-difficulty-distribution)); band edges are data-driven tertiles over the RandomFuzz-reachable
contracts, so a level means the same in both corpora. Table rows = methods; each column = one dataset × level
(**E**=EASY / **N**=NORMAL / **H**=HIGH / **I**=IMPOSSIBLE) with the level's contract count in the header;
cell = detection rate (k/n). An IMPOSSIBLE contract needs a value RandomFuzz cannot draw, so a nonzero I cell
is a guided method that detected it anyway. Figures = the two per-dataset heatmaps (left = DeFi, right = SB).

# Part D · SSCFuzz internals

*SSCFuzz per-iteration logs only; RL-greedy vs ε-random picks (ε = ~uniform strategy sample). 9 strategies =
5 generation + 4 mutation.*

## D1. Per-strategy search yield

![DeFiHackLabs](../figures/experiment/D1_strategy_yield.png)
![SmartBugs](../figures/experiment_smartbugs/D1_strategy_yield.png)

*How to read:* mean new bytecode-branches/iter per strategy (ε-unbiased vs greedy-realized); blue = generation,
orange = mutation. Taller = more new coverage per call.

## D2. Strategy × vulnerability class (genuine)

![DeFiHackLabs](../figures/experiment/D2_strategy_by_class.png)
![SmartBugs](../figures/experiment_smartbugs/D2_strategy_by_class.png)

*How to read:* distinct contracts each strategy genuinely first-solved per class (genuine = the iteration's
own call created a bug its seed did not have). A diagonal = specialists.

## D3. Mutation: genuine vs inherited

![DeFiHackLabs](../figures/experiment/D3_mutation_genuine_vs_inherited.png)
![SmartBugs](../figures/experiment_smartbugs/D3_mutation_genuine_vs_inherited.png)

*How to read:* of mutation bug-iterations, green = genuine (seed had no bug), grey = inherited (spurious).
More green = more real mutation contribution.

## D4. Selection vs yield

![DeFiHackLabs](../figures/experiment/D4_selection_vs_yield.png)
![SmartBugs](../figures/experiment_smartbugs/D4_selection_vs_yield.png)

*How to read:* x = unbiased yield (D1), y = RL greedy selection share; upper-right = budget on high-yield
strategies.

## D5. RL-greedy vs ε-random

![DeFiHackLabs](../figures/experiment/D5_greedy_vs_random.png)
![SmartBugs](../figures/experiment_smartbugs/D5_greedy_vs_random.png)

*How to read:* mean reward / new-branches of greedy vs ε-random picks within the same runs, per iteration bin.
Compare the two lines per panel.

## D6. Strategy selection over iterations

![DeFiHackLabs](../figures/experiment/D6_selection_by_iter.png)
![SmartBugs](../figures/experiment_smartbugs/D6_selection_by_iter.png)

*How to read:* fraction of contracts choosing each strategy at each iteration (5-iter smoothed); generation
above the cyan line, mutation below. Bright band = a strategy the policy concentrates on.

# Part E · Oracle precision

## E1. FinanceFuzz — detected property vs planted class

![DeFiHackLabs](../figures/experiment/E1_ff_property_by_class.png)
![SmartBugs](../figures/experiment_smartbugs/E1_ff_property_by_class.png)

*How to read:* each FinanceFuzz detection by detected property (TOD / Gasless / Timestamp / Reentrancy) ×
planted class; only `Reentrancy × reentrancy` is on-target. Bar = detection count under generous (any
property) vs strict (property matches planted class).

## E2. Detection & union under strict scoring

| quantity | DeFiHackLabs | SmartBugs |
|---|---|---|
| FF detection — generous | 1/25 | 6/33 |
| FF detection — strict | 0/25 | 0/33 |
| 5 in-house union | 14/25 | 16/33 |
| union + FF (generous) | 14/25 | 21/33 |
| union + FF (strict) | 14/25 | 16/33 |
| FF unique solves (generous / strict) | 0 / 0 | 5 / 0 |

*How to read:* generous counts any property; strict counts only detections whose property matches the planted
class. "union + FF" shows FF's marginal contribution over the 5 in-house methods.

## E3. In-house signal caveat — PLN

PLN (`2024-09_PLN`, DeFiHackLabs) is the documented false-positive trap for the financial-loss oracle: a
naive "gained PLN tokens" check (`attacker_gained` heuristic) fires with no *net* profit (the attacker also
paid WETH). The net-profit oracle (`attacker_profit`) suppresses it — in these runs no method flags PLN. The
in-house signal is an *outcome* (real value extraction), precise about loss but not mechanism (see
`research/related_work/oracle_financial_loss_research.md`).

---

## Caveats & reproduction

- **Single run per contract** — no variance estimate; treat ±1 contract as noise (~3 pp SB / ~4 pp DeFi).
- **Detection rate** (contracts-with-bug) is the robust metric; per-iteration "total bugs" is inflated.
- **FinanceFuzz coverage** is sampled once per generation (coarse lower bound).
- **LLM backend sizes (B1–B8):** 1.5B = base run (`output/experiment/`); 3B / 7B = sibling runs
  (`output/experiment_llama3b/`, `output/experiment_llama7b/`), swept only for the 3 LLM-driven methods
  (`madfuzz`/`llmfuzz`/`sscfuzz`). The 7B sweep is still partial (SSCFuzz + LLMFuzz complete; MADFuzz not
  run) — unavailable cells shown as `—`. B9/B10 + Parts C–E use the 1.5B run; Part A is model-independent.
- **Reproduce** (from repo root):
  `uv run python src/experiment/eda/exp_analysis.py {defihacklabs,smartbugs,all}` (Parts A–C, B);
  `uv run python src/experiment/eda/model_compare.py {defihacklabs,smartbugs,all}` (B1 per-model columns → `B1_by_model.csv`);
  `uv run python src/experiment/eda/eda_enrich_partA.py` (A1 vuln dist + feature stats);
  `uv run python src/experiment/eda/sscfuzz_internals.py {defihacklabs,smartbugs,all}` (Part D);
  `uv run python src/experiment/eda/oracle_precision.py {defihacklabs,smartbugs,all}` (Part E).
