"""FinanceFuzz competitor baseline.

A faithful reimplementation of FinanceFuzz (Gan et al., 2025) — its ABI-driven seed
generation, ConFuzzius evolutionary engine, and financial-property oracle (token-supply
invariant + the four equivalence detectors with T→T′ construction) — executed on this
project's forge harness instead of the upstream instrumented py-evm. Reference source:
`ref/FinanceFuzz`. See `.README_AGENT.md` for the documented backend adaptations.
"""

from .runner import run_financefuzz

__all__ = ["run_financefuzz"]
