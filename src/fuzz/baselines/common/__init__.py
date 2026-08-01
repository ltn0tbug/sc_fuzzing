"""Shared building blocks for RLFuzz and MADFuzz baselines."""

from .grouping import RLFUZZ_GROUPS, MADFUZZ_GROUPS, classify_functions
from .state import BaselineState, BaselineStateEncoder
from .config import BaselineConfig, resolve_external_addrs
from .loop import run_baseline_loop

__all__ = [
    "RLFUZZ_GROUPS",
    "MADFUZZ_GROUPS",
    "classify_functions",
    "BaselineState",
    "BaselineStateEncoder",
    "BaselineConfig",
    "resolve_external_addrs",
    "run_baseline_loop",
]
