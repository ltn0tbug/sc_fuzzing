# Experiment Analysis — SmartBugs-Curated

*Single dataset: 33 curated single-file contracts (one planted vuln each), 100 iters/contract, 6 methods. The
3 LLM-driven methods (MADFuzz / LLMFuzz / SSCFuzz) are additionally swept over 1.5B / 3B / 7B backends across Part B's method-comparison views (B1–B8 — each backend size shown as its own bar / line / box / column / table row); the SSCFuzz-internal sections (B9, B10) and Parts C–E stay on the 1.5B backend.
Figures: `research/figures/experiment_smartbugs/`. Reproduce: see [combined](experiment_analysis_combined.md#caveats--reproduction).*

> **Reading guide.** This file is **results only** — every section is a table or a figure with a short
> *how-to-read* caption (axes + what "good" looks like). No interpretation/claims here; those live in
> `research/research.md` and the paper. Sibling reports:
> [defihacklabs](experiment_analysis_defihacklabs.md) · [combined](experiment_analysis_combined.md) (side-by-side) ·
> [pooled](experiment_analysis_pooled.md) (both as one corpus).

<!-- TOC -->
## Contents

- [Setup](#setup)
- [Part A · Dataset EDA](#part-a--dataset-eda)
  - [A1. Vulnerability-class distribution](#a1-vulnerability-class-distribution)
  - [A2. Static feature profile](#a2-static-feature-profile)
  - [A3. Feature collinearity](#a3-feature-collinearity)
  - [A4. Sample difficulty distribution](#a4-sample-difficulty-distribution)
- [Part B · Method results](#part-b--method-results)
  - [B1. Detection & coverage](#b1-detection--coverage)
  - [B2. Coverage growth](#b2-coverage-growth)
  - [B3. Coverage distribution](#b3-coverage-distribution)
  - [B4. Time-to-first-bug](#b4-time-to-first-bug)
  - [B5. SSCFuzz vs each baseline (paired)](#b5-sscfuzz-vs-each-baseline-paired)
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

<!-- /TOC -->

## Setup

| | |
|---|---|
| Benchmark | SmartBugs-curated — small single-file contracts, one planted vuln class each |
| Paired set | 33 contracts (all 6 methods completed, status ok) |
| Budget | 100 iterations / contract / method |
| Methods | `randomfuzz` · `financefuzz` · `rlfuzz` · `madfuzz` · `llmfuzz` · `sscfuzz` (ours) |
| LLM backends (B1–B8) | 1.5B (base) · 3B · 7B — swept for `madfuzz`/`llmfuzz`/`sscfuzz` only |

# Part A · Dataset EDA

*Static structure of the 33 contracts — no fuzzing results, so identical across LLM backend sizes; the
backend comparison lives in Part B's method-comparison figures + the B1 / B5 tables.*

## A1. Vulnerability-class distribution

![vuln-class distribution](../figures/A1_vuln_distribution_smartbugs.png)

| class | n |
|---|---|
| reentrancy | 18 |
| access_control | 11 |
| arithmetic | 3 |
| unchecked_low_level_calls | 1 |

*How to read:* labelled vuln class per contract; this `n` is the per-class denominator used in B8.

## A2. Static feature profile

| feature | median (mean) |
|---|---|
| `loc` | 26 (48) |
| `cyclomatic_complexity` | 4 (5.9) |
| `total_fn_count` | 4 (4.9) |
| `external_fn_count` | 4 (4.2) |
| `max_branches_per_fn` | 2 (3.2) |
| `defi_action_count_total` | 2 (1.9) |
| `require_count` | 1 (1.3) |
| `constraint_density` | 0.02 (0.04) |

*How to read:* central tendency of each static feature over the 33 contracts (compare against DeFiHackLabs in
[combined A2](experiment_analysis_combined.md#a2-static-feature-profile--median-mean-per-corpus)).

## A3. Feature collinearity

![feature correlation](../figures/experiment_smartbugs/A3_feature_corr.png)

*How to read:* Spearman ρ between every pair of static features; darker = more correlated (redundant).

## A4. Sample difficulty distribution

![sample difficulty](../figures/experiment_smartbugs/A4_gen_difficulty_dist.png)

*How to read:* one bar per contract; **bar height = self-information `H = log₂(RandomFuzz search-space size) = −log₂ P`**,
the probability the blind RandomFuzz baseline draws a satisfying input in one try (so expected random draws
≈ 2^H) — computed from the ground-truth PoC, no fuzzer run. Each call adds `log₂(F)` (F = callable functions
= `external_fn_count`); each constrained argument adds `log₂(pool)` where the pool is RandomFuzz's draw set
(address corpus = declared externals + `hardcoded_address_count`; small-value/constant pool = `magic_number_count`); a coordinate RandomFuzz CANNOT draw takes the full type domain (2²⁵⁶ / 2¹⁶⁰): a runtime-derived `$ret` value, a specific on-chain address not in the seeded corpus, or a numeric literal outside RandomFuzz's boundary/scale pool (a keccak storage slot or an arbitrary large amount); a burn/zero address (`0x…dEaD` / `0x0`) is an arbitrary recipient → free. **Color = difficulty level:** EASY · NORMAL · HIGH are data-driven tertiles of H over the RandomFuzz-reachable contracts
(dotted lines = tertile edges); IMPOSSIBLE = needs a RandomFuzz-unreachable coordinate, bars capped
for display. This corpus: EASY 9 · NORMAL 10 · HIGH 10 · IMPOSSIBLE 4.

# Part B · Method results

## B1. Detection & coverage

| method | det 1.5B | det 3B | det 7B | cov 1.5B | cov 3B | cov 7B |
|---|---|---|---|---|---|---|
| RandomFuzz | 33 % (11/33) | 33 % (11/33) | 33 % (11/33) | 0.643 | 0.643 | 0.643 |
| FinanceFuzz | 18 % (6/33) | 18 % (6/33) | 18 % (6/33) | 0.566 | 0.566 | 0.566 |
| RLFuzz | 39 % (13/33) | 39 % (13/33) | 39 % (13/33) | 0.729 | 0.729 | 0.729 |
| MADFuzz | 33 % (11/33) | 39 % (13/33) | — | 0.697 | 0.691 | — |
| LLMFuzz | 36 % (12/33) | 48 % (16/33) | 48 % (16/33) | 0.643 | 0.690 | 0.682 |
| SSCFuzz (ours) | 39 % (13/33) | 48 % (16/33) | 45 % (15/33) | 0.716 | 0.727 | 0.730 |

![detection & coverage by backend size](../figures/experiment_smartbugs/B1_detection_coverage_by_model.png)

*How to read:* det = fraction of the paired contracts with ≥1 bug (k/n in parens); cov = mean bytecode-branch
coverage ratio. The three sub-columns per metric are the LLM backend size — 1.5B / 3B / 7B of one model family.
RandomFuzz / FinanceFuzz / RLFuzz do not call the LLM, so their size columns repeat one run. `—` = that size's
run is not available for this set (absent, partial, or unfinished). **Figure:** one bar per method × backend
size — coloured by method, darker = bigger backend; LLM-free methods appear once, and a size with no complete
run has no bar. (FinanceFuzz detection validity → Part E.)

## B2. Coverage growth

![coverage growth](../figures/experiment_smartbugs/B2_coverage_growth_by_model.png)

*How to read:* x = iteration, y = cumulative mean coverage; higher and still-rising = better. Each LLM-driven method is one line per backend size (1.5B / 3B / 7B; darker = bigger); RandomFuzz / FinanceFuzz / RLFuzz appear once.

## B3. Coverage distribution

![coverage box](../figures/experiment_smartbugs/B3_coverage_box_by_model.png)

*How to read:* over the 33 contracts, higher median + tighter spread = better. One box per (method × backend size) — LLM-driven methods get a box per size (1.5B / 3B / 7B, darker = bigger), LLM-free once.

## B4. Time-to-first-bug

![time to bug](../figures/experiment_smartbugs/B4_time_to_bug_by_model.png)

*How to read:* Kaplan–Meier — y = fraction of contracts still without a bug at iteration x; dropping early
and low = better. Flat-high lines = bug not found within budget (right-censored). One line per (method × backend size), darker = bigger backend; LLM-free methods appear once.

## B5. SSCFuzz vs each baseline (paired)

| baseline (method × backend size) | Δ mean cov | Cliff's δ | Wilcoxon p | McNemar p (detection) |
|---|---|---|---|---|
| RandomFuzz | +0.073 | +0.54 | <0.001 | 0.688 |
| FinanceFuzz | +0.150 | +0.79 | <0.001 | 0.143 |
| RLFuzz | −0.013 | −0.07 | 0.093 | 1.000 |
| MADFuzz·1.5B | +0.019 | +0.05 | 0.132 | 0.625 |
| MADFuzz·3B | +0.025 | +0.16 | 0.056 | 1.000 |
| LLMFuzz·1.5B | +0.073 | +0.50 | 0.0002 | 1.000 |
| LLMFuzz·3B | +0.026 | +0.24 | 0.055 | 0.375 |
| LLMFuzz·7B | +0.034 | +0.33 | 0.005 | 0.375 |
| SSCFuzz·3B | −0.011 | −0.07 | 0.388 | 0.375 |
| SSCFuzz·7B | −0.014 | −0.09 | 0.239 | 0.625 |

*How to read:* reference = **SSCFuzz·1.5B (ours)**; Δcov = ours − the row's (method × backend size), positive =
ours covers more; the SSCFuzz·3B/·7B rows compare bigger backends of our own method against 1.5B.
|Cliff's δ|>0.47 = large effect; p<0.05 = significant. Paired over the 33 contracts.

## B6. Complementarity & head-to-head

![detection heatmap](../figures/experiment_smartbugs/B6_detection_heatmap_by_model.png)

| method × backend size | unique solves | total solves |
|---|---|---|
| RandomFuzz | 0 | 11 |
| FinanceFuzz | 3 | 6 |
| RLFuzz | 0 | 13 |
| MADFuzz·1.5B | 0 | 11 |
| MADFuzz·3B | 0 | 13 |
| LLMFuzz·1.5B | 0 | 12 |
| LLMFuzz·3B | 0 | 16 |
| LLMFuzz·7B | 1 | 16 |
| SSCFuzz·1.5B | 0 | 13 |
| SSCFuzz·3B | 0 | 16 |
| SSCFuzz·7B | 0 | 15 |

*How to read:* heatmap = which (method × backend size) (column) solves which contract (row); green = ≥1 bug.
Rows are sorted hardest→easiest by PoC difficulty (A4), each contract prefixed with its level initial
(`E`=EASY / `N`=NORMAL / `H`=HIGH / `I`=IMPOSSIBLE). unique solves = contracts no other (method × size) finds.
Union over all method × backend size = 22/33 (any-signal; strict scoring → E2).

## B7. Cost efficiency

![cost efficiency](../figures/experiment_smartbugs/B7_cost_efficiency_by_model.png)

*How to read:* bugs per 1k LLM tokens (Random/RL are token-free); upper-left / higher = cheaper per bug. One bar per (method × backend size), darker = bigger; token-free methods (Random/RL) are omitted.

## B8. Detection by vulnerability class

![category detection](../figures/experiment_smartbugs/B8_category_detection_by_model.png)

*How to read:* rows = vulnerability class, columns = each (method × backend size); cell = detection rate on that class (k-with-bug / class n), greener = higher. LLM-driven methods span 1.5B / 3B / 7B (left→right), LLM-free (Random/Finance/RL) appear once; a size with no complete run is omitted. (Classes differ by corpus; FinanceFuzz credit is by reported signal → Part E.)

## B9. Action selection

![action selection](../figures/experiment_smartbugs/B9_selection_heatmap.png)

*How to read:* fraction of a method's iterations spent on each strategy / function-group / mutation choice
(RandomFuzz excluded). Flat = broad exploration; concentrated = narrow policy.

## B10. Sequence depth × width

![depth × width bug-rate](../figures/experiment_smartbugs/B10_depthwidth_bugrate.png)

*How to read:* per generated sequence, depth = #calls, width = #distinct functions; cell = bug-rate of that
shape (pooled over methods). Hotter = shapes more likely to trigger a bug.

# Part C · Feature ↔ outcome

*Static features (Part A) joined to outcomes (Part B), Spearman over the 33 contracts.*

## C1. Feature ↔ coverage

![feature vs coverage](../figures/experiment_smartbugs/C1_feature_vs_coverage.png)

*How to read:* ρ between each feature and mean coverage; negative = harder to cover, |ρ| larger = stronger.

## C2. Feature ↔ solvability

![feature vs solvability](../figures/experiment_smartbugs/C2_feature_vs_solvability.png)

*How to read:* solvability = how many of the 6 methods find a bug; ρ vs each feature (negative = harder).

## C3. Breadth × depth

![breadth × depth](../figures/experiment_smartbugs/C3_breadth_depth.png)

*How to read:* contracts split at the within-dataset median breadth (`total_fn_count`) × depth
(`max_branches_per_fn`) → 4 quadrants; cell shows the coverage-winning method per quadrant.

## C4. Generation difficulty (PoC-derived) ↔ solvability

![gen difficulty × detection](../figures/experiment_smartbugs/C4_gen_difficulty.png)

| method | EASY (9) | NORMAL (10) | HIGH (10) | IMPOSSIBLE (4) |
|---|---|---|---|---|
| RandomFuzz | 0.78 (7/9) | 0.30 (3/10) | 0.10 (1/10) | 0.00 (0/4) |
| FinanceFuzz | 0.11 (1/9) | 0.20 (2/10) | 0.30 (3/10) | 0.00 (0/4) |
| RLFuzz | 1.00 (9/9) | 0.20 (2/10) | 0.20 (2/10) | 0.00 (0/4) |
| MADFuzz | 1.00 (9/9) | 0.20 (2/10) | 0.00 (0/10) | 0.00 (0/4) |
| LLMFuzz | 0.89 (8/9) | 0.40 (4/10) | 0.00 (0/10) | 0.00 (0/4) |
| SSCFuzz (ours) | 1.00 (9/9) | 0.20 (2/10) | 0.10 (1/10) | 0.25 (1/4) |

*How to read:* rows = methods; columns = PoC-difficulty level, left→right **EASY** (n=9) · **NORMAL** (n=10) ·
**HIGH** (n=10) · **IMPOSSIBLE** (n=4), each with its contract count in the header. Each cell = that method's
detection rate on that level (rate over k/n); greener = higher rate. Level = RandomFuzz reachability (defined
in [A4](#a4-sample-difficulty-distribution)): an IMPOSSIBLE contract needs a value RandomFuzz cannot draw, so
a nonzero IMPOSSIBLE cell is a guided method that detected it anyway.

# Part D · SSCFuzz internals

*SSCFuzz per-iteration logs only. Each iteration is RL-greedy (`fallback=False`) or ε-random
(`fallback=True`); under ε the strategy is ~uniform (unbiased yield sample). 9 strategies = 5 generation + 4
mutation.*

## D1. Per-strategy search yield

![per-strategy yield](../figures/experiment_smartbugs/D1_strategy_yield.png)

*How to read:* mean new bytecode-branches/iter per strategy, on ε-random (unbiased) vs greedy (realized)
picks; blue = generation, orange = mutation. Taller = more new coverage per call.

## D2. Strategy × vulnerability class (genuine)

![strategy × class](../figures/experiment_smartbugs/D2_strategy_by_class.png)

*How to read:* distinct contracts each strategy **genuinely** first-solved per class (genuine = the
iteration's own call created a bug its immediate seed did not have). A diagonal = specialists.

## D3. Mutation: genuine vs inherited

![mutation genuine vs inherited](../figures/experiment_smartbugs/D3_mutation_genuine_vs_inherited.png)

*How to read:* of mutation iterations that report a bug, green = genuine (seed had no bug), grey = inherited
(seed already buggy → spurious credit). More green = more real mutation contribution.

## D4. Selection vs yield

![selection vs yield](../figures/experiment_smartbugs/D4_selection_vs_yield.png)

*How to read:* x = unbiased yield (D1), y = RL greedy selection share; upper-right = budget concentrated on
high-yield strategies.

## D5. RL-greedy vs ε-random

![greedy vs random](../figures/experiment_smartbugs/D5_greedy_vs_random.png)

*How to read:* mean reward / new-branches of greedy vs ε-random picks within the same runs, per iteration bin
(binning controls for new-coverage decay). Compare the two lines per panel.

## D6. Strategy selection over iterations

![selection by iter](../figures/experiment_smartbugs/D6_selection_by_iter.png)

*How to read:* fraction of contracts choosing each strategy at each iteration (5-iter smoothed); generation
above the cyan line, mutation below. A bright horizontal band = a strategy the policy concentrates on.

# Part E · Oracle precision

*Whether a reported bug signal corresponds to the planted vulnerability.*

## E1. FinanceFuzz — detected property vs planted class

![FF property × class](../figures/experiment_smartbugs/E1_ff_property_by_class.png)

*How to read (left):* each FinanceFuzz detection by detected property (rows: TOD / Gasless / Reentrancy) ×
planted class (cols); only `Reentrancy × reentrancy` is on-target. *(right):* detection count under
**generous** (any property fires) vs **strict** (detected property matches planted class).

## E2. Detection & union under strict scoring

| quantity | n / 33 |
|---|---|
| FF detection — generous | 6 |
| FF detection — strict | 0 |
| 5 in-house union | 16 |
| union + FF (generous) | 21 |
| union + FF (strict) | 16 |
| FF unique solves (generous / strict) | 5 / 0 |

*How to read:* generous counts any property; strict counts only detections whose property matches the planted
class. "union + FF" shows FF's marginal contribution over the 5 in-house methods.
