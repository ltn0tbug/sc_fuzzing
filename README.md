# sc-fuzzing

> Smart contract fuzzer combining Reinforcement Learning, LLM-guided input generation, and Foundry execution.

## About This Release

This repository is the **artifact release for ICPADS-2026** — the *IEEE International
Conference on Parallel and Distributed Systems*, 2026 edition — accompanying the paper:

> **Strategy-Driven Smart Contract Fuzzing with Reinforcement Learning and LLM-Based Input Generation**

It contains the fuzzer implementation (`src/`), the evaluation datasets (`data/`), the raw
per-contract experiment results every reported number is computed from (`output/`), the
analysis reports and figures used in the paper (`research/`), and the dataset/analysis
tooling (`utils/`).

**Layout at a glance**

| Path | Contents |
|---|---|
| `src/fuzz/` | The fuzzer: RL controller, LLM agent, Foundry execution engine, baselines |
| `src/experiment/` | Full-dataset experiment runner + analysis (EDA) scripts |
| `data/` | SmartBugs-curated and DeFiHackLabs dataset layers + contract sources |
| `output/experiment/` | Main results (Claude backend), per dataset × method × contract |
| `output/experiment_llama3b/`, `output/experiment_llama7b/` | LLM backend-size sweep results |
| `research/analysis_experiment_results/` | Analysis reports the paper's claims are drawn from |
| `research/figures/` | Generated figures and CSV tables |

---

Traditional fuzzers mutate bytes randomly. Smart contracts have ABI-structured inputs and semantic state dependencies — random bytes rarely produce valid or interesting calls. This tool learns *which* attack strategy to apply (RL) and generates *semantically meaningful* transaction sequences for that strategy (LLM), executed against the real EVM via Foundry.

---

## How It Works

```
Contract Source + ABI
        ↓
   Static Analysis (AST features)
        ↓
┌────────────────────────────────────────┐
│            Fuzzing Loop                │
│                                        │
│  Payoff stats → Selector → Strategy    │
│                     ↓                  │
│     LLMGenerator → Fuzz Inputs         │
│          or                            │
│     LLMMutator   → Mutated Inputs      │
│                     ↓                  │
│          Foundry → Results             │
│                     ↓                  │
│    Coverage / Bug Reward → Selector    │
└────────────────────────────────────────┘
        ↓
   Bug Report (JSON)
```

**Three components:**

| Component | Role | Technology |
|-----------|------|------------|
| Strategy Selector | Selects attack strategy + mode (gen vs mut) | Exhaustion-Switching Bandit (default) · DQN / LinUCB variants |
| LLM Agent | Generates / mutates transaction sequences | Claude or llama-cpp |
| Execution Engine | Runs inputs, measures coverage, detects bugs | Foundry + EVM |

**On the selector.** Bare `sscfuzz` runs `sscfuzz_esb`, an **Exhaustion-Switching Bandit**
(`BanditController`) — **no neural network, and no encoded state vector at all**: it ignores
the encoder output and keeps its own per-arm payoff bookkeeping (warm up over all arms, pin
any quick-win exploit, exploit the best *recent*-payoff arm while it keeps finding new
branches, then eliminate that arm after `bandit_giveup` unproductive picks and move on).
The neural variants are opt-in and selected by name — `sscfuzz_dqn` (factored per-arm-head
DQN over a 52-dim per-arm state layout) and `sscfuzz_cb` (disjoint LinUCB contextual bandit
over a 12-dim context). Only those two consume the `StateEncoder` vector — see
*SScFuzz selector* under [Fuzzing Strategies](#fuzzing-strategies) below.

The selector picks from **17 strategies**: 7 generation strategies (the LLM authors an input from scratch) + 10 mutation strategies (the LLM transforms a corpus seed). The LLM handles the creative work of crafting inputs within the chosen strategy. Foundry provides ground-truth bytecode-level branch coverage and revert data.

---

## Fuzzing Strategies

There are 17 strategies in two families. **Generation strategies** (actions 0–6) — the LLM authors an input from scratch:

| # | Generation strategy | Targets |
|---|----------|---------|
| 0 | `reentrancy_probe` | CEI violations, ETH callbacks |
| 1 | `arithmetic_probe` | Integer overflow / underflow + numeric off-by-one / boundary |
| 2 | `access_control_probe` | Missing auth, `onlyOwner` bypasses |
| 3 | `price_oracle_probe` | Price-oracle manipulation, share-pricing / token-accounting attacks |
| 4 | `logic_error_probe` | Broken invariants, faulty accounting |
| 5 | `boundary_values` | Off-by-one, edge cases (gated off by default — folded into `arithmetic_probe`) |
| 6 | `exploration` | Broad coverage — diverse function sequences (gated off by default in RL Iter 7 — breadth already supplied by the ε-random input injection + per-strategy coverage reward) |

**Mutation strategies** (actions 7–16) — the LLM transforms a corpus seed (with a deterministic ABI-level fallback): `value_perturb`, `arg_boundary`, `caller_swap`, `call_insert`, `call_delete`, `call_shuffle`, `reentry_depth`, `arg_address`, `call_swap`, `arg_shuffle`.

By default SScFuzz **gates off** 8 strategies (`FuzzerConfig.disabled_strategies`): the 5 dead mutations `arg_boundary`, `caller_swap`, `call_delete`, `call_shuffle`, `reentry_depth` (0 unique solves); `boundary_values` (folded into `arithmetic_probe`); `arg_address` (generalized by `arg_shuffle`, which rewrites an argument of any type); and `exploration` (RL Iter 7 — pure breadth, redundant with the ε-random input injection + per-strategy coverage reward, and the DQN's mis-concentration magnet). This leaves an **active roster of 5 generation + 4 mutation = 9** (mutations: `value_perturb`, `call_insert`, `arg_shuffle`, `call_swap`). All 17 stay defined; an empty blocklist restores the full roster for the ablation. The controller head is a **hard resize** to the active roster — `action_dim` is synced to the compact action-table length (9 for SScFuzz), not a masked head over a fixed 17.

### SScFuzz selector — a bandit default + a DQN and a contextual-bandit variant

The **`sscfuzz`** method name is an **alias for `sscfuzz_esb`** (the switching bandit below) — the RQ3a finding is that an *encoded* bandit, not a *learned* DQN, is the right selector at this per-contract horizon, so it is the recommended default. The three selectors share the entire pipeline (reward, corpus, warmup, ε-random input, LLM roster + gate) and differ **only in the strategy selector**, making them clean selector ablations that each write to their own result dir:

- **`sscfuzz_esb`** (what bare `sscfuzz` runs) — an **Exhaustion-Switching Bandit** (`BanditController`, no neural net): warms up over all arms, pins any quick-win exploit, exploits the best *recent*-payoff arm while it keeps finding new branches, and after `bandit_giveup` unproductive picks eliminates that arm (cooldown) and moves to the next. Encodes the switch policy the DQN cannot learn from a <200-iter cold start.
- **`sscfuzz_dqn`** (the former default) — a **factored shared-per-arm-head DQN** over the encoder's **per-arm state layout** (52-dim: a 7-dim global-context block + one 5-dim tuple `(tanh avg_reward, tanh mrew, dry, bug_trace, is_mut)` per active arm). One shared sub-net scores every arm from its own tuple + the global context, pooling the "pick a rising / not-dried arm" rule across arms (the cross-arm generalization a flat MLP cannot do). Folds in the recency/exhaustion signals (`mrew`/`dry`) the earlier `sscfuzz_ms` fed as separate state blocks.
- **`sscfuzz_cb`** — a **disjoint LinUCB contextual bandit** (`ContextualBanditController`, no neural net): each strategy gets its own discounted linear model `θ_a` over a small arm-independent context (process signals + the 5 static contract features), selecting `argmax θ_aᵀx + α√(xᵀA_a⁻¹x)`. Because each arm owns its `θ_a`, the contract features route *per strategy* ("has external calls ⇒ reentrancy arm") and the weights transfer across contracts via `--load-model`/`--save-model` — where the factored DQN collapsed to a contract-agnostic average.

Run via the experiment registry (e.g. `uv run python src/experiment/run/run.py sscfuzz --dataset smartbugs --only <id>`); all reuse `run_fuzzing_loop`.

---

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) — package manager
- [Foundry](https://getfoundry.sh/) — `forge` must be in PATH
- One of the LLM backends below

---

## Installation

```bash
git clone <repo>
cd sc-fuzzing
uv sync
```

---

## LLM Backends

| Backend | Auth | Notes |
|---------|------|-------|
| `anthropic` | `ANTHROPIC_API_KEY` | default; calls API directly |
| `claude-code` | local `claude` CLI | Agent SDK; no key needed; `uv pip install "sc-fuzzing[claude-code]"` |
| `llama-cpp` | none | local server at `--backend-url`; GBNF-constrained output |

---

## Usage

### Fuzz a contract

```bash
export ANTHROPIC_API_KEY=sk-ant-...
uv run sc-fuzz sscfuzz <foundry_project> <ContractName> \
  --source <path/to/Contract.sol> \
  --abi    <path/to/Contract.json> \
  --iterations 100
```

End-to-end smoke test with the included example:

```bash
cp data/examples/VulnerablePool.sol vault_test/src/
forge build --root vault_test
uv run sc-fuzz sscfuzz vault_test VulnerablePool \
  --source vault_test/src/VulnerablePool.sol \
  --abi    vault_test/out/VulnerablePool.sol/VulnerablePool.json \
  --iterations 50 --debug
```

`vault_test/` is a pre-scaffolded Foundry project. `VulnerablePool.sol` exercises all 7 bug classes.

### Baselines

```bash
uv run sc-fuzz rlfuzz     <project> <Contract> --abi ... --source ...   # group DQN + seed-value random args
uv run sc-fuzz madfuzz    <project> <Contract> --abi ... [--no-llm-seed] [--llm-pool-prob 0.3]
uv run sc-fuzz randomfuzz <project> <Contract> --abi ... --source ...   # pure uniform random
uv run sc-fuzz llmfuzz    <project> <Contract> --abi ... [--backend anthropic]     # LLM-only, uniform gen+mut roster (no RL)
```

### Scaffold a new project

```bash
uv run sc-fuzz init-project ./new_project MyContract
```

---

## Output

Found bugs are written to `output/bugs.json`:

```json
{
  "summary": {
    "method": "sscfuzz",
    "contract": "VulnerablePool",
    "generated_at": "2026-06-05T...",
    "total_bugs": 2,
    "strategies_used": ["reentrancy_probe", "arithmetic_probe"]
  },
  "bugs": [
    {
      "iteration": 12,
      "strategy": "reentrancy_probe",
      "bug_signal_found": true,
      "signals": ["attacker_gained"],
      "description": "deposit 1 ETH then re-enter withdraw via fallback"
    }
  ]
}
```

---

## Project Structure

```
sc-fuzzing/
├── src/fuzz/
│   ├── config.py              RLConfig, LLMConfig, FuzzerConfig, ForkConfig (schema)
│   ├── profiles.py            Per-method defaults (sscfuzz/rlfuzz/madfuzz/…)
│   ├── report.py              ReportSpec/REPORT_SPECS — gates console panels + JSON fields
│   ├── main.py                CLI (click) — commands only; calls orchestrator
│   ├── orchestrator.py        run_fuzzing_loop (SScFuzz iteration driver) + build_bugs_payload
│   ├── rl/                    network.py · replay_buffer.py · controller.py · bandit.py (make_controller)
│   ├── llm/
│   │   ├── strategies.py      17 strategies (7 generation + 10 mutation) + prompt tables
│   │   ├── agent.py           _LLMClient + FuzzInput (re-export hub for backends/source_budget)
│   │   ├── backends.py        LLM backends (anthropic/claude-code/llama-cpp) + GBNF + TokenUsage
│   │   ├── source_budget.py   Solidity minify · ABI signatures · AST slice · source budget
│   │   ├── generator.py       LLMGenerator: generate(strategy)
│   │   └── prompts/           system · generation · mutation · seed_pool · chatml
│   ├── fuzzer/
│   │   ├── foundry.py         FoundryFuzzer (render/run/coverage/oracle)
│   │   ├── sol_interface.py   ABI→Solidity interface + pragma/mode detection (pure fns)
│   │   ├── results.py         FuzzResult + CoverageStats (leaf dataclasses)
│   │   ├── coverage.py        Bytecode-level coverage (replaces forge coverage)
│   │   ├── paths.py           exploit-path novelty (jaccard / is_distinct_path)
│   │   ├── mutator.py         LLMMutator: corpus + ABI mutation-strategy fallbacks + llm_mutate
│   │   ├── reward.py          compute_reward()
│   │   ├── state.py           ContractFeatures + StateEncoder (layout-dependent: 7/12-dim context · 52-dim per-arm · block fallback; unused by the default bandit)
│   │   └── templates/         Harness.sol (shared oracle + attacker) · inline · inline_legacy · fork · finance · finance_legacy · finance_fork (.sol.tpl)
│   └── baselines/             rlfuzz · madfuzz · randomfuzz · llmfuzz · financefuzz · common/
├── src/experiment/            Full-dataset experiment harness (code only)
│   ├── dataloader/            schema.py loader + JSON schemas (data lives in ./data/)
│   ├── run/                   run.py (unified CLI) + registry.py + scaffold.py + exp_profile.py
│   └── eda/                   Outcome analysis (features/outcomes/dataframe.py)
├── data/                      Datasets (json layers + source/ + CHANGELOG.md) — generated by utils/, never under src/
│   └── examples/              Standalone example contracts (VulnerablePool.sol — all 7 bug classes · FF_*.sol — FinanceFuzz fixtures)
├── utils/                     Shared tooling — dataset builders/validators/fetchers + analysis (xlsx)
├── output/                    Experiment results (tracked) → output/experiment*/<dataset>/<method>/*.json; ad-hoc single runs → output/*.json (gitignored)
├── CLAUDE.md                  Router for agents (auto-loaded) → points at per-module .README_AGENT.md docs
└── research/                  analysis_experiment_results/ (analysis reports) + figures/ (figures + CSV tables) — human-facing
```

---

## Reward Function

```
+40 × (new_bc_branches / total)    branch coverage discovery (deduped globally)   [baseline path]
+50 / +5                           per distinct exploit path, paid once (path-gated, tiered)
+10 × (novel_branches / total)     seed divergence (mutation mode only)           [baseline path]
```

The coverage and novelty terms are normalized by contract size so the selector sees a
comparable signal across contracts. **SScFuzz (RL Iter 7) replaces the single coverage
term above with a two-tier signal** (the block above is the baseline path RLFuzz / MADFuzz /
LLMFuzz keep): a small **per-strategy base** paid every run for branches new to *that*
strategy's own history (anti-starvation — a late-arriving vuln strategy is never zeroed on
already-globally-seen branches, the front-loaded coverage lottery that anti-selected it),
plus a larger **global-new bonus** gated by (past a round-robin warmup **and** a real
coverage plateau) and amplified by the plateau multiplier — so only hard-won post-plateau
frontier advances pay and the easy early sweep crowns no winner. The novelty term is dropped
on this path (per-strategy coverage subsumes it). The bug term is tiered and path-gated: a novel
exploit path with a **confirmed net impact** (a `tier=high` signal — `attacker_profit`
or `target_loss`, proved by valuing the whole bag: through the on-chain DEX on a fork, or
via a mock/empty DEX that prices native-coin holdings only when running inline) pays +50;
a path backed only by a `tier=heuristic` balance-move signal (which may
be a fair trade) pays +5. It is the *max* tier present, never a sum, and pays out only
the first time a path is seen — re-running a known exploit is still *detected* but earns
no further reward.

---

## Results

Every number in the ICPADS-2026 paper is computed from the raw per-contract run records in
`output/`. The derived reports and figures are checked in alongside them:

- [`research/analysis_experiment_results/`](research/analysis_experiment_results/) — analysis
  reports per dataset (`experiment_analysis_smartbugs.md`, `experiment_analysis_defihacklabs.md`)
  plus the combined and pooled views.
- [`research/figures/`](research/figures/) — figures (PNG) and the CSV tables behind them.

To regenerate them from `output/`, see the analysis commands in
[`COMMANDS.md`](COMMANDS.md).

---

## Architecture Notes

See [`CLAUDE.md`](CLAUDE.md) for the development guide (picked up automatically in
AI-assisted sessions), and the per-module `.README_AGENT.md` files under `src/` for
component-level detail.

---

## License

MIT
