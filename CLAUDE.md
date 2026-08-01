# CLAUDE.md — agent router

Router, not encyclopedia. Orient, then open the one file for the task. Module detail =
each area's `.README_AGENT.md`.

> **ICPADS-2026 artifact release.** This is the public snapshot published with the paper
> *Strategy-Driven Smart Contract Fuzzing with Reinforcement Learning and LLM-Based Input
> Generation* (IEEE International Conference on Parallel and Distributed Systems, 2026).
> The internal dataset-authoring rules (`rule/`), paper sources (`report/`), test suite
> (`tests/`), and working notes (`todo.md`, `research/research.md`) are not part of it —
> routes below that referenced them have been dropped.

## MANDATORY RULES (always in effect — keep in mind every task)
1. **Docs split.** Agent docs are `.README_AGENT.md` (terse, for you) — when you want a module/area guide,
   open its `.README_AGENT.md`, **never** a `README.md`. `README.md` is
   **human-facing**: don't treat it as your source of truth and don't rewrite it.
2. **Commands** live in `COMMANDS.md` — run from there, don't reinvent invocations.
3. **Scratch in `.tmp_agent/`.** Put throwaway scripts, test runs, and temp output in the repo-local
   `.tmp_agent/` folder (gitignored), **never** `/tmp`.
4. **Results are evidence.** `output/experiment*/` holds the published ICPADS-2026 run records —
   every reported number derives from them. Don't overwrite or regenerate them in place.
5. **Don't ask when told to self-decide.** If the user has said to decide things yourself (e.g. a long
   unattended session), **never** call AskUserQuestion — pick the best option, note it, and proceed.
6. **Docs follow code — same task.** Any code change that invalidates a documented fact (counts,
   names, action ranges, CLI flags, config/schema fields, log contracts, `src/` tree) MUST fix
   **every** doc stating it — `.README_AGENT.md`, docstrings/comments, **and** human-facing
   `README.md`/`CLAUDE.md`/`COMMANDS.md` (the one case you edit these:
   keeping them factually correct isn't the "rewrite" rule 1 forbids). Code is the source of truth;
   grep the changed symbol repo-wide and fix all hits. **Before reporting done — even after a
   compaction — re-grep for stale refs.** "I'll compact" never excuses skipping the sweep.

## Route by task — open ONLY the match
| Task | File |
|---|---|
| reward/search-signal · DQN · replay · strategy selection | `src/fuzz/rl/.README_AGENT.md` |
| strategies · prompts · LLM backends · FuzzInput output contract | `src/fuzz/llm/.README_AGENT.md` |
| execution · fork financial-loss oracle · coverage · corpus · templates · ctor/dep deploy · declared-external/`$ret` | `src/fuzz/fuzzer/.README_AGENT.md` |
| config schema · per-method defaults · report fields · CLI · data flow · add baseline/method | `src/fuzz/.README_AGENT.md` |
| dataset loader · JSON `schemas/` (data lives in repo-root `./data/`) | `src/experiment/dataloader/.README_AGENT.md` |
| run full-dataset experiments | `src/experiment/run/.README_AGENT.md` |
| EDA / outcome analysis | `src/experiment/eda/.README_AGENT.md` |
| **any command to run** | `COMMANDS.md` |
| architecture · component roles · full `src/` tree | `README.md` (human-facing) |
| published results · analysis reports · figures | `research/analysis_experiment_results/` · `research/figures/` |

## What
SC fuzzer. RL(DQN) picks strategy+mode → LLM(Claude/llama.cpp) gen/mutate a tx sequence →
Foundry/EVM runs + measures coverage → shaped reward updates DQN.
Stack: py3.12 · uv · torch · Anthropic SDK (+Agent SDK/llama.cpp opt) · Foundry · click+rich · pytest.
