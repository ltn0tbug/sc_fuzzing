"""Result dataclasses for a fuzz run — the leaf data types `foundry.py` produces.

Split out of `foundry.py` so the many consumers that only need the *shape* of a
run result (`reward.py`, `state.py`, `baselines/*`, `report.py`, `paths.py`) can
import it without dragging in the ~1500-line Foundry executor. `foundry.py` and
`fuzzer/__init__.py` re-export these names, so every existing
`from .foundry import FuzzResult` / `from .fuzzer import FuzzResult` still works.
"""

from dataclasses import dataclass, field


@dataclass
class FuzzResult:
    """Result from executing one fuzz input.

    Coverage fields:
      - branches_*:    source-level (forge convention) — logged for human reading
      - bc_branches_*: bytecode-level (raw JUMPI×direction) — drives reward
      - lines_*:       per-source-line coverage (logged for human interpretation)
      - functions_*:   per-function coverage (logged for human interpretation)
    """
    coverage: float = 0.0         # [0, 1] fraction of bc_branches covered cumulatively (matches reward signal)
    # Fork only: the recompiled artifact's opcode stream drifted from the on-chain
    # deployed bytecode, so the SOURCE tier (branches_*/lines_*) is untrustworthy
    # and suppressed (0/0). bc_branches_* + functions_* stay valid (on-chain-
    # anchored). Always False inline. Surfaced in the run_log summary + _summary.json.
    coverage_unreliable: bool = False
    new_branches: int = 0         # source-level new branches (run-log)
    branches_total: int = 0       # source-level total (run-log)
    branches_this_run: frozenset = field(default_factory=frozenset)
    # ── Bytecode-level branch coverage (drives reward) ────────────────────────
    new_bc_branches: int = 0
    bc_branches_total: int = 0
    bc_branches_this_run: frozenset = field(default_factory=frozenset)  # (jumpi_pc, direction)
    bc_branch_hit_counts: dict = field(default_factory=dict)
    # ── Line coverage (run-log only — does not affect reward) ─────────────────
    lines_this_run: frozenset = field(default_factory=frozenset)
    new_lines: int = 0
    lines_total: int = 0
    line_hit_counts: dict = field(default_factory=dict)
    # ── Function coverage (run-log only — does not affect reward) ─────────────
    functions_this_run: frozenset = field(default_factory=frozenset)
    new_functions: int = 0
    functions_total: int = 0
    function_hit_counts: dict = field(default_factory=dict)
    # ── Test outcome ──────────────────────────────────────────────────────────
    reverted: bool = False
    forge_status: str = "Success" # forge "status" ("Success"|"Failure"), or "CompileError"/"SetupFailed" (synthesised)
    revert_reason: str = ""       # "assertion_failed", "arithmetic_overflow", "custom_error", "out_of_gas", "reverted", "compile_error", "fork_setup_failed" (transient fork-RPC failure — createSelectFork setup OR mid-execution storage fetch; retried in run_input)
    raw_reason: str = ""          # verbatim forge "reason" field before classification
    gas_used: int = 0
    bug_signal_found: bool = False       # True iff a BUG_SIGNAL line appeared in decoded_logs (recall)
    high_bug_signal_found: bool = False  # True iff any bug_signal is tier=high (a proved net profit/loss — precision)
    new_exploit_path: int = 0      # 1 iff bug_signal_found AND the exploit path is novel (Jaccard<0.9) — drives bug reward
    bug_path_dup_of: int = -1     # when not rewarded: index of the already-rewarded exploit path it duplicates; -1 otherwise
    bug_type: str = ""            # "reentrancy" | "drain" (derived from the BUG_SIGNAL strategy)
    bug_signals: list = field(default_factory=list)  # parsed BUG_SIGNAL lines: [{name,tier,asset,token_address,total_asset,target_asset,amount}]
    trace: str = ""
    call_depth: int = 0
    decoded_logs: list = field(default_factory=list)  # console.log lines from the test


@dataclass
class CoverageStats:
    """Cumulative branch coverage at both granularities.

    `branches_*` are source-level (forge convention, run-log + lcov).
    `bc_branches_*` are bytecode-level — match the reward signal and the
    `coverage` ratio inside `FuzzResult`. Console/summary display uses bc.
    """
    branches_hit: int = 0
    branches_total: int = 0
    bc_branches_hit: int = 0
    bc_branches_total: int = 0
    # Fork only: source tier (branches_*) untrustworthy — bc is on-chain-anchored
    # and always valid; the source ratio should not be trusted. See FuzzResult.
    coverage_unreliable: bool = False

    @property
    def ratio(self) -> float:
        """Source-level ratio — preserved for backwards compatibility / lcov."""
        return self.branches_hit / self.branches_total if self.branches_total else 0.0

    @property
    def bc_ratio(self) -> float:
        return self.bc_branches_hit / self.bc_branches_total if self.bc_branches_total else 0.0
