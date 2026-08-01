"""Iteration-level checkpointing for resumable long fuzzing runs.

The experiment runner resumes at **contract** granularity (skips ids already in
`_summary.json`). That's too coarse for very-long runs: a contract killed at
iteration 480/500 restarts from 0. This module adds the **inner** layer — every
method's loop (sscfuzz in `orchestrator.py`, the four baselines in
`baselines/common/loop.py`) flushes a checkpoint every `checkpoint_every`
iterations, so an interrupt resumes mid-contract from the last flushed point
(≤ `checkpoint_every` iterations of rework, not the whole run).

Design:
- One dict per (method, contract), written atomically via `torch.save` (handles
  DQN tensors + arbitrary picklable state: sets, deques, dataclasses, FuzzInputs).
- The loop gathers component sub-states through each stateful component's
  `checkpoint_state()` and restores them via `restore_checkpoint_state()`
  (or, for policies, `state_dict()`/`load_state_dict()`). Static structure
  (interfaces, function ranking, ABI) is reconstructed deterministically at
  compile time, so only the *evolving* state is persisted.
- Flush is disk-only (not held in memory across iterations) so a 500-iteration
  run doesn't accumulate per-iteration snapshots.
- Deleted on clean completion by the runner; a stale/corrupt/older-version file
  is ignored (run starts fresh) rather than crashing the run.

The growing **run-record log** (one dict per iteration, embedding the fuzz
input/output and — for LLM methods — the prompt/response, so KB–tens-of-KB
each) is deliberately NOT part of the checkpoint dict. Re-serializing the whole
list every flush would be O(n) memory + O(n²/interval) IO on a very-long run —
exactly the runs checkpointing exists for. Instead each record is *appended* to
a sidecar JSON-lines file (`append_record`) as it's produced, and read back on
resume (`load_records`, truncated to the checkpoint's iteration so records from
rolled-back iterations after the last flush are dropped). Appends are O(1); the
checkpoint blob itself stays small and constant-size.

`checkpoint_every <= 0` disables checkpointing entirely.
"""

from __future__ import annotations

import json
import logging
import os
import random
from pathlib import Path

import numpy as np
import torch

logger = logging.getLogger(__name__)

# Bump when the checkpoint dict layout changes incompatibly; older files are
# then ignored (run restarts) instead of mis-restoring into a changed schema.
CHECKPOINT_VERSION = 1


def checkpoint_path(method_dir: str | Path, safe_id: str) -> Path:
    """Location of a (method, contract) checkpoint: <method_dir>/_ckpt/<safe_id>.ckpt.pt."""
    return Path(method_dir) / "_ckpt" / f"{safe_id}.ckpt.pt"


def records_path(ckpt_path: str | Path) -> Path:
    """Sidecar run-record log next to a checkpoint: <...>.ckpt.pt → <...>.records.jsonl."""
    p = Path(ckpt_path)
    # strip the ".ckpt.pt" double suffix, then add ".records.jsonl"
    stem = p.name[: -len(".ckpt.pt")] if p.name.endswith(".ckpt.pt") else p.stem
    return p.with_name(f"{stem}.records.jsonl")


def append_record(rec_path: str | Path, record: dict) -> None:
    """Append one run-record as a JSON line (O(1) — never rewrites the file).

    Best-effort: a serialization/IO failure here must not kill the fuzzing run,
    since the record log is telemetry + resume aid, not correctness-critical."""
    rec_path = Path(rec_path)
    try:
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        with rec_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:  # noqa: BLE001 — telemetry write, never fatal
        logger.warning("run-record append failed (%s) — continuing without it", e)


def load_records(rec_path: str | Path, before_iteration: int) -> list[dict]:
    """Read the sidecar log, keeping only records from iterations < `before_iteration`.

    The checkpoint is flushed every `checkpoint_every` iters but records are
    appended every iter, so after a mid-interval crash the log holds records for
    iterations the restored RL/coverage state has already rolled back. Keeping
    only `rec["iteration"] < before_iteration` (the checkpoint's completed-iter
    count) realigns the two; the file is rewritten to that kept prefix so later
    appends don't duplicate. Absent/corrupt file ⇒ [] (run continues, log rebuilt)."""
    rec_path = Path(rec_path)
    if not rec_path.exists():
        return []
    kept: list[dict] = []
    try:
        with rec_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue  # tolerate a torn final line from a crash mid-write
                if r.get("iteration", 0) < before_iteration:
                    kept.append(r)
    except Exception as e:  # noqa: BLE001 — non-fatal, start the log fresh
        logger.warning("run-record load failed (%s) — starting this contract's log fresh", e)
        return []
    # Rewrite to the kept prefix so subsequent appends stay consistent.
    try:
        tmp = rec_path.with_suffix(rec_path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            for r in kept:
                f.write(json.dumps(r) + "\n")
        os.replace(tmp, rec_path)
    except Exception as e:  # noqa: BLE001
        logger.warning("run-record truncate failed (%s)", e)
    return kept


def rng_state() -> dict:
    """Snapshot the process RNG state (python / numpy / torch) for a seamless resume."""
    return {
        "python": random.getstate(),
        "numpy": np.random.get_state(),
        "torch": torch.get_rng_state(),
    }


def restore_rng(state: dict | None) -> None:
    if not state:
        return
    random.setstate(state["python"])
    np.random.set_state(state["numpy"])
    torch.set_rng_state(state["torch"])


def save(path: str | Path, state: dict) -> None:
    """Atomically write a checkpoint dict (torch.save to a temp file + os.replace)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    torch.save({**state, "_version": CHECKPOINT_VERSION}, tmp)
    os.replace(tmp, path)  # atomic on POSIX — no half-written checkpoint on crash


def load(path: str | Path) -> dict | None:
    """Load a checkpoint, or None if absent / unreadable / version-mismatched.

    Failures are non-fatal: a corrupt or older-schema checkpoint means the run
    simply restarts from iteration 0 rather than crashing."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        state = torch.load(path, weights_only=False)
    except Exception as e:  # noqa: BLE001 — any unpickling failure → start fresh
        logger.warning("checkpoint load failed (%s) — starting this contract fresh", e)
        return None
    if not isinstance(state, dict) or state.get("_version") != CHECKPOINT_VERSION:
        logger.warning("checkpoint version/format mismatch — starting this contract fresh")
        return None
    return state


def clear(path: str | Path) -> None:
    """Delete a checkpoint + its run-record sidecar (called on clean completion)."""
    Path(path).unlink(missing_ok=True)
    records_path(path).unlink(missing_ok=True)
