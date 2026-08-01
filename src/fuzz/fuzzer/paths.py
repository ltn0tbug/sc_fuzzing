"""Exploit-path similarity — shared by the reward bug-gate (foundry/reward) and
the corpus bug-witness group (mutator). One definition of 'distinct exploit'.

Kept dependency-free on purpose: `reward.py` imports `foundry.py`, so this
helper must NOT live in `reward.py` (would create an import cycle). Both the
reward gate and the corpus Group-B selection import `is_distinct_path` here so
"distinct attack path" means exactly the same thing in both places.

An exploit run is identified by its bytecode-level branch set
(`FuzzResult.bc_branches_this_run` — (jumpi_pc, direction) pairs). Two exploits
are the "same attack path" iff those sets are >= EXPLOIT_PATH_SIM_THRESHOLD
Jaccard-similar; a padded rerun of an exploit hits essentially the same branches
as its lean core, so it collapses onto the same path.
"""
from __future__ import annotations

EXPLOIT_PATH_SIM_THRESHOLD = 0.9  # >= this Jaccard ⇒ same attack path (a rerun)


def jaccard(a: frozenset, b: frozenset) -> float:
    """|a ∩ b| / |a ∪ b|. Two empty sets are defined identical (1.0)."""
    if not a and not b:
        return 1.0
    union = len(a | b)
    return len(a & b) / union if union else 1.0


def is_distinct_path(
    sig: frozenset, witnesses, threshold: float = EXPLOIT_PATH_SIM_THRESHOLD,
) -> bool:
    """True iff `sig` is < threshold similar to EVERY witness.

    An empty witness list ⇒ True (the first exploit is always distinct).
    """
    return all(jaccard(sig, w) < threshold for w in witnesses)
