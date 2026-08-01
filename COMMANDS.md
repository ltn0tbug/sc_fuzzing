# COMMANDS — cheatsheet

All runnable commands, one place. Agent reference + human copy-paste.

## Setup
```bash
uv sync                                   # install
```

## Fuzz one contract (full method)
`--backend {anthropic|claude-code|llama-cpp}` · `--approach {whitebox|greybox}` ·
needs `export ANTHROPIC_API_KEY=sk-ant-...` for anthropic.
```bash
uv run sc-fuzz sscfuzz ./project MyContract \
  --abi out/MyContract.sol/MyContract.json --source src/MyContract.sol \
  --iterations 100 [--debug] [--strategy reentrancy_probe] \
  [--temperature 0.7] [--max-tokens 4096] [--max-source-chars 24000] \
  [--run-log-path PATH] [--bug-report-only]
```

## Baselines (same flag shape)
```bash
uv run sc-fuzz rlfuzz     ...
uv run sc-fuzz madfuzz    ... [--no-llm-seed] [--llm-pool-prob 0.3]
uv run sc-fuzz randomfuzz ... [--reentrancy-prob 0.25]
uv run sc-fuzz llmfuzz    ... [--backend anthropic]
# FinanceFuzz competitor (own GA + financial-property oracle; no flag shape — uses GA knobs):
uv run sc-fuzz financefuzz <proj> <Contract> --abi … --source … \
  [--generations 8] [--population 12] [--max-calls 20] [--equivalence-elite 4]
uv run sc-fuzz init-project ./new_project MyContract     # scaffold a Foundry project
```

## FinanceFuzz competitor smoke (needs forge; no LLM/key)
```bash
# fixtures: data/examples/FF_{TransferMint,TOD,Timestamp,Reentrancy,GaslessSend,Benign}.sol
cp data/examples/FF_Reentrancy.sol vault_test/src/ && forge build --root vault_test
uv run sc-fuzz financefuzz vault_test FF_Reentrancy \
  --abi vault_test/out/FF_Reentrancy.sol/FF_Reentrancy.json \
  --source data/examples/FF_Reentrancy.sol --generations 3 --population 6
```

## End-to-end smoke (needs forge + ANTHROPIC_API_KEY)
```bash
cp data/examples/VulnerablePool.sol vault_test/src/ && forge build --root vault_test
uv run sc-fuzz sscfuzz vault_test VulnerablePool \
  --source vault_test/src/VulnerablePool.sol \
  --abi vault_test/out/VulnerablePool.sol/VulnerablePool.json --iterations 50 --debug
```

## Experiments (registry-driven; method × dataset)
`method ∈ {sscfuzz|sscfuzz_dqn|sscfuzz_esb|sscfuzz_cb|rlfuzz|madfuzz|randomfuzz|llmfuzz|financefuzz|all}` ·
resumable (skips ids in `_summary.json`). **`sscfuzz` is an ALIAS for `sscfuzz_esb`** (the switching-bandit
selector — RQ3a-recommended — writing to the `sscfuzz_esb/` dir); `sscfuzz_dqn` is the factored-DQN selector
(former default); `sscfuzz_cb` is the LinUCB contextual bandit. `all` runs each canonical method once (uses
`sscfuzz_dqn`, not the alias). NOTE: `financefuzz` is modern-pragma (>=0.8) only — legacy SmartBugs rows are
skipped (logged); its inline fixtures + the comparable rows are its ground.
```bash
uv run python src/experiment/run/run.py <method> --dataset smartbugs|defihacklabs \
  [--mode test(15)|medium(50)|long(100)|very_long(500)] [--iterations N] \
  [--backend …] [--only <id>] [--verify] [--output-dir <path>] [--no-skip-on-fail] [--checkpoint-every N] [--keep-checkpoint] [--debug]
# --output-dir <path> (default output/experiment/): override the results ROOT — a full registry run
#   lands under <path>/<dataset>/<method>/ (still resumable). Use it to run without clobbering canonical
#   results, or to send throwaway/smoke output to .tmp_agent/ instead of _verify/.
# --checkpoint-every N (default 25, 0=off): inner iteration-level resume — a contract killed mid-run
#   (Ctrl+C/OOM) resumes from the last flush (<method_dir>/_ckpt/) on re-run, not from iter 0.
# --keep-checkpoint: on CLEAN completion keep a final checkpoint at the TRUE last iter (not cleared);
#   re-run the same contract with a higher --iterations to CONTINUE (e.g. 100 → 200), not restart.

uv run python src/experiment/run/run.py all --dataset smartbugs --mode test     # every method
uv run python src/experiment/run/run.py sscfuzz --dataset smartbugs --only <id> --verify   # spot-check
# Continue a finished contract for 100 more iters (needs --keep-checkpoint on BOTH runs):
uv run python src/experiment/run/run.py sscfuzz --dataset smartbugs --only <id> --iterations 100 --keep-checkpoint
uv run python src/experiment/run/run.py sscfuzz --dataset smartbugs --only <id> --iterations 200 --keep-checkpoint
```

Standalone runs are resumable/continuable too via `--checkpoint-path PATH` (off by default) +
`--keep-checkpoint` (all methods except financefuzz):
```bash
uv run sc-fuzz sscfuzz ./proj C --abi … --source … --iterations 100 --checkpoint-path ck.pt --keep-checkpoint
uv run sc-fuzz sscfuzz ./proj C --abi … --source … --iterations 200 --checkpoint-path ck.pt --keep-checkpoint  # +100
```

## Dataset (find/validate/add a row)
```bash
uv run python src/experiment/dataloader/schema.py                         # per-dataset counts
uv run python utils/validate_defihacklabs_bugsignal.py --only <name>   # fork-validate a poc (require attacker_gained/attacker_profit)
```
Fetch verified source (chases proxies; bare id, no `defihacklabs/` prefix):
```python
import sys; sys.path.insert(0, "utils"); import fetch_defihacklabs_sources as F
F.save_one(F.load_env_key(), target_id="2023-04_Swapos", chain="mainnet", address="0x8ce2…", force=False)
```
Read fork state: `cast call <addr> "<sig>" <args> --rpc-url <RPC> --block <N>`  (RPCs in `src/experiment/run/scaffold.py:RPC_ENDPOINTS` — now chain→**list**, use any entry).

Validate every layer file against `schemas/`:
```bash
uv run python - <<'PY'
import json; from jsonschema import Draft202012Validator
for ds in ("smartbugs_curated","defihacklabs"):
    for layer in ("raw","manifest","enrich"):
        s=json.load(open(f"src/experiment/dataloader/schemas/{layer}.schema.json"))
        d=json.load(open(f"data/{ds}/{layer}.json"))
        e=list(Draft202012Validator(s).iter_errors(d)); print(("OK " if not e else f"FAIL({len(e)}) ")+f"{ds}/{layer}")
PY
```

## EDA
```bash
cd src/experiment/eda && uv run python dataframe.py                    # row counts + columns
# Experiment-analysis battery → research/figures/ + the 4 research/analysis_experiment_results/experiment_analysis_*.md reports.
# Run from repo root:
uv run python src/experiment/eda/exp_analysis.py {defihacklabs,smartbugs,all}   # A–C, B
uv run python src/experiment/eda/model_compare.py {defihacklabs,smartbugs,all}  # B1 per-model cols + B11 backend-size heatmap
uv run python src/experiment/eda/eda_enrich_partA.py                            # A1 vuln dist + feature stats
uv run python src/experiment/eda/sscfuzz_internals.py {defihacklabs,smartbugs,all}  # Part D
uv run python src/experiment/eda/oracle_precision.py {defihacklabs,smartbugs,all}   # Part E
uv run python src/experiment/eda/vuln_type_analysis.py                          # per-class scoreboard CSVs
# (A PCA/MI/Kaplan-Meier/Mann-Whitney survey notebook existed during development but its
#  outputs were unused by the reports; it is not part of this release.)
```
