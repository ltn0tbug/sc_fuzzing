"""Experiment-wide profile — picks the iteration-budget regime and a few
cross-runner knobs (LLM backend, skip-on-fail, MADFuzz seed knobs).

Per-method *hyperparameter defaults* live in `fuzz.profiles`:
each runner does `<method>_defaults.materialize(mode=EXPERIMENT_MODE, …)`.
This file therefore only owns the "which regime + which backend" choice;
to change the RL hyperparameters for one method, edit
`src/fuzz/profiles.py` (the corresponding *Defaults class).

See research.md §10 Q8 for the per-regime tuning rationale.

Available regimes (selected by `EXPERIMENT_MODE`):
  test       → 15 iter — debug / smoke
  medium     → 50 iter — light experiments
  long       → 100 iter — recommended for paper-grade comparisons
  very_long  → 500 iter — exhaustive sweeps
"""

from __future__ import annotations

# ── Iteration-budget regime ───────────────────────────────────────────────────
EXPERIMENT_MODE: str = "test"

# ── Cross-method overrides ────────────────────────────────────────────────────
# Switching the LLM backend on a single line — applies to sscfuzz + madfuzz.
LLM_BACKEND: str = "llama-cpp"  # "anthropic" | "claude-code" | "llama-cpp"

# ── Runner behavior ───────────────────────────────────────────────────────────
SKIP_ON_FAIL: bool = True    # True → log failure and continue; False → abort
# Inner (iteration-level) resume cadence: every method's loop flushes its full
# resumable state every N iterations so a contract interrupted mid-run resumes
# from the last flush instead of restarting at 0 (the runner's contract-level
# resume is the outer layer). 0 disables. See fuzz/checkpoint.py.
CHECKPOINT_EVERY: int = 25

# ── MADFuzz-only knobs ────────────────────────────────────────────────────────
USE_LLM_SEED: bool = True    # disable to ablate the LLM seed pool
LLM_POOL_PROB: float = 0.3   # P(sample arg from LLM seed pool) per step
