"""State encoder for the RL controller.

THREE emitted layouts (precedence in encode(): context → per-arm → block):

**Context layout** (`context_layout`, the contextual-bandit `sscfuzz_cb` — disjoint
LinUCB, selector rework 2026-07-13). Emits ONLY the shared global-context block
(N_GLOBAL=7 process dims + the N_STATIC=5 F1 contract features when emit_static) —
the arm-INDEPENDENT context vector `x` for LinUCB. The per-strategy separation is
carried by each arm's own linear model `θ_a` (rl/contextual_bandit.py), so — unlike
the per-arm layout — the context deliberately holds NO per-arm features; F1 in `x`
routes per-strategy natively (θ_reentrancy learns a positive weight on
has_external_calls). state_dim = N_GLOBAL + (N_STATIC if emit_static else 0) = 7 or 12.

**Per-arm layout** (`per_arm_layout`, the `sscfuzz_dqn` method — the factored
shared-per-arm-head DQN, selector rework 2026-07-10). A global-context block
(N_GLOBAL=7) followed by one contiguous ARM_FEAT=5 tuple per ACTIVE arm (G gen
slots then M mut slots, matching the orchestrator action table). Each tuple =
(tanh(avg_reward), tanh(mrew EWMA), dry/DRY_NORM, bug_trace, is_mut). The factored
head (network.py) runs ONE shared sub-net over each arm's tuple + the global
context, so the learned "pick a rising / not-dried arm" rule pools across all arms
(anti-starvation). For the 5-gen+4-mut SScFuzz roster → state_dim = 7 + 5·9 = 52
(emit_static off, canonical); with emit_static the global block grows 7→12 → 57.
See the N_GLOBAL / ARM_FEAT class doc for `_encode_per_arm`. Dropped vs the block
layout: revert (measured non-contributing), stuck (subsumed by gen/mut_stall),
seed_pool_mean (co-moves with best). mrew/dry (retired `sscfuzz_ms` recency/
exhaustion signals) are folded in as per-arm tuple features.

**Block layout** (`per_arm_layout` off — the baselines' full-roster ablation and
the `sscfuzz_esb` bandit, which discards the vector). Two per-strategy reward
blocks (gen then mut) hold one dim per ACTIVE gen strategy (G, RL Iter 4 gate) and
one per ACTIVE mut strategy (M, RL Iter 5); DYNAMIC-DECISION-ONLY (RL Iter 6): the
5 static contract features + 2 heat-map aggregates were dropped, gen/mut-stall +
seed-pool dims added. Full gen roster (G=7), flags off → state_dim 17. Optional
gated block: bug-success trace (emit_bug_trace, +G+M). The block-layout map below:

  [0]              coverage_ratio
  [1]              coverage_velocity (last 10 iters)
  [2]              stuck_counter / 100
  [3 .. 2+G]       avg_reward per ACTIVE gen strategy (G dims)  ← the gold: state→gen-strategy signal
  [3+G .. 2+G+M]   avg_reward per ACTIVE mut strategy (M dims)  ← RL Iter 5: state→mut-strategy signal
  [bug-trace block] decaying bug-success trace per ACTIVE strategy (G+M dims, gen
                    then mut) — GATED OFF by default (emit_bug_trace, RL Iter 7 C3);
                    bumps on a novel exploit bank, fades ×bug_trace_decay each round
  [static block]   5 static contract features — GATED OFF by default (emit_static)
  [off_revert]     avg_revert_rate
  [off_dyn+0]      frontier_saturation           ← mean of the FRONTIER_K branch-frontier dims
  [off_dyn+1]      corpus_maturity               ← corpus fill fraction (RL Iter 3: gen→mut timing)
  [off_dyn+2]      gen_stall                     ← RL Iter 6: iters since a GEN action found a new bc-branch / STALL_NORM
  [off_dyn+3]      mut_stall                     ← RL Iter 6: iters since a MUT action found a new bc-branch / STALL_NORM
  [off_dyn+4]      seed_pool_value_mean          ← RL Iter 6: mean corpus-seed reward (are the seeds worth mutating?)
  [off_dyn+5]      seed_pool_value_best          ← RL Iter 6: max corpus-seed reward

**RL Iter 6 dynamic-decision reshape.** The 5 static contract features are
CONSTANT within a single-contract run (the net is rebuilt per contract) → dead
input dims; the 2 heat-map aggregates (mean-func-cov, frac-touched) duplicated
`coverage_ratio`. All three groups were dropped from the emitted vector (the
static block is kept behind `emit_static`, default off, so cross-contract
ablation is one flag away; the heat-map accumulators keep running). In their
place: `gen_stall`/`mut_stall` (the gen-vs-mut discriminator — mutation is the
right move when generation has gone stale) and `seed_pool_value_mean/best` (is
the corpus worth exploiting?). The reward's action-agnostic un-stick multiplier
(reward.py) pays for breaking a plateau; these dims let the policy SEE when to.

**RL Iter 4 strategy gate.** Disabled generation strategies never get selected,
so their per-strategy reward slot stayed 0 forever — a dead DQN input dim. The
encoder now takes `active_gen_mask` (from `disabled_strategies`) and emits a
reward slot ONLY for active gen strategies, shrinking the network input to match
the gated roster. `update()` maps a full gen index → compact slot via `_slot_of`.

**RL Iter 2 compression (89 → 19).** The prior encoder emitted a 64-dim
per-function heat-map (2 channels × FUNC_K=32) — 72% of the vector — whose *only*
consumer was the DQN. Per-function coverage doesn't map to a vuln-class/breadth
*strategy* choice, so those 64 dims were ~noise that drowned the [3-9] per-strategy
reward signal at a ~92-train-step budget. They are replaced by **3 aggregates**
([16] mean function coverage, [17] fraction of functions touched this iter, [18]
frontier saturation). The `avg_gas_last_10` dim was also dropped as weak. The
heat-map / frontier *accumulation* still runs (cheap) — only the emitted vector
shrinks; the full-89 layout is one constant away if a regression appears.

**Frontier channel (source, now aggregated).** Function-level coverage is binary
per function ("did we enter `withdraw`"), too coarse on small contracts where ~all
branches live in 2-3 functions. The frontier accumulator tracks, for the FRONTIER_K
hottest source-line branch decisions, how many directions were taken:
  0.0 = branch site never reached
  0.5 = reached, only one direction taken  ← on the exploration frontier
  1.0 = both directions taken (fully explored)
reusing the per-direction `(line, direction)` data the reward already collects
(`FuzzResult.branches_this_run`). [18] emits the mean of those FRONTIER_K values.

Function ordering (for accumulation) is top-K by branch count (attack-surface
proxy), deterministic per contract; the tail (functions ranked FUNC_K..N)
aggregates into the last slot. FUNC_K=32 / FRONTIER_K=8 sized for the datasets.

Compared to the prior 21-dim encoder, removed:
  - assertion_hits  : reward no longer scores reverts (stale signal)
  - overflow_hits   : same reason
  - unauthorized_hits: was never written (dead dim)
  - max_call_depth  : monotonic high-water counter that never reset (saturating)
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

import numpy as np

from .foundry import FuzzResult

if TYPE_CHECKING:
    from .coverage import BytecodeMeta


# Per-function coverage heat-map width. Two channels (total + current) → 2*FUNC_K dims.
FUNC_K = 32

# Branch-frontier channel width — tracks explored/frontier/unexplored status of the
# FRONTIER_K hottest source-line branch decisions. One channel → FRONTIER_K dims.
FRONTIER_K = 8

# Normalizer for the gen/mut stall counters (RL Iter 6): iters-since-last-progress
# / STALL_NORM, clamped to 1. Matches the stuck_counter's /100 so the three
# plateau signals sit on the same scale.
STALL_NORM = 100.0

# Normalizer for the seed-pool value dims (RL Iter 6): raw corpus-seed reward /
# SEED_VALUE_NORM, clamped to [0,1]. Sized to the high bug-signal score (50) so a
# banked-exploit seed reads near 1.0 and routine coverers read near 0.
SEED_VALUE_NORM = 50.0

# Bump applied to a strategy's decaying bug-success trace (RL Iter 7 C3) when it
# banks a NOVEL exploit path. 1.0 (clamped) → one bank saturates the trace; it then
# fades ×bug_trace_decay each round, giving a bounded recency foothold the policy
# can prefer AFTER the one-shot (path-gated) bug reward has evaporated.
BUG_TRACE_BUMP = 1.0

# Normalizer for the per-arm exhaustion (dry) tuple feature: consecutive-
# unproductive picks of a strategy / DRY_NORM, clamped to 1. Sized to a handful
# of dead rounds (≈ the bandit_giveup regime) so the
# exhaustion signal saturates around the point a switch is due, rather than the
# whole-run scale STALL_NORM (=100) uses for the global gen/mut-stall dims.
DRY_NORM = 20.0

# Divisor for the tanh squash of the per-arm reward / EWMA dims in the per-arm
# layout (`per_arm_layout`). Raw rewards run +2 (one branch) → +50 (a banked
# exploit), an unbounded scale that would dominate the L2 norm of an otherwise
# [0,1] state vector and swamp the bounded process signals a scale-sensitive MLP
# reads. tanh(reward / REWARD_TANH_NORM) folds them into (−1, 1) alongside the
# rest. Matches the baseline encoder's tanh(avg_r / 50) so the two stay comparable.
REWARD_TANH_NORM = 50.0


class ContractFeatures:
    """Static features extracted from a contract at analysis time."""

    def __init__(
        self,
        num_functions: int = 0,
        num_payable: int = 0,
        has_external_calls: bool = False,
        has_delegatecall: bool = False,
        cyclomatic_complexity: int = 1,
    ):
        self.num_functions = num_functions
        self.num_payable = num_payable
        self.has_external_calls = has_external_calls
        self.has_delegatecall = has_delegatecall
        self.cyclomatic_complexity = cyclomatic_complexity

    @classmethod
    def from_source(cls, source: str, abi: list[dict]) -> "ContractFeatures":
        """Heuristically extract features from Solidity source and ABI.

        Legacy regex fallback — used only when the AST isn't available
        (e.g. older artifacts compiled without `forge build --ast`).
        Prefer `from_ast` when possible: regex on raw source false-positives
        on comments and misses lib-imported calls.
        """
        num_functions = sum(1 for item in abi if item.get("type") == "function")
        num_payable = sum(
            1 for item in abi
            if item.get("type") == "function" and item.get("stateMutability") == "payable"
        )
        has_external_calls = "call{" in source or ".call(" in source or "transfer(" in source
        has_delegatecall = "delegatecall" in source
        branch_keywords = ["if ", "else", "for ", "while ", "require(", "revert("]
        complexity = 1 + sum(source.count(kw) for kw in branch_keywords)

        return cls(
            num_functions=num_functions,
            num_payable=num_payable,
            has_external_calls=has_external_calls,
            has_delegatecall=has_delegatecall,
            cyclomatic_complexity=complexity,
        )

    @classmethod
    def from_ast(cls, ast: dict, abi: list[dict]) -> "ContractFeatures":
        """Extract features from the solc AST. Deterministic ground truth —
        replaces regex heuristics that were tripped by comments / strings /
        identifier substrings.

        Walks every node once. Counts:
          - num_functions: ABI functions (excluding constructors/fallbacks).
          - num_payable:   `FunctionDefinition` with `stateMutability=payable`.
          - has_external_calls: any `MemberAccess` whose `memberName ∈ {call, transfer, send}`.
          - has_delegatecall:   any `MemberAccess` whose `memberName == delegatecall`.
          - cyclomatic_complexity: 1 + count of `IfStatement`, `Conditional`,
            `WhileStatement`, `DoWhileStatement`, `ForStatement`, `&&`/`||`
            BinaryOperations, and `require`/`assert` calls. Matches the AST
            branch set used for source-level coverage so the two stay in sync.
        """
        num_functions = sum(1 for item in abi if item.get("type") == "function")
        num_payable = 0
        has_external_calls = False
        has_delegatecall = False
        complexity = 1
        stack: list = [ast] if ast else []
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            nt = node.get("nodeType")
            if nt == "FunctionDefinition":
                if node.get("stateMutability") == "payable":
                    num_payable += 1
            elif nt == "MemberAccess":
                member = node.get("memberName", "")
                if member == "delegatecall":
                    has_delegatecall = True
                    has_external_calls = True
                elif member in ("call", "transfer", "send"):
                    has_external_calls = True
            elif nt in ("IfStatement", "Conditional", "WhileStatement",
                         "DoWhileStatement", "ForStatement"):
                complexity += 1
            elif nt == "BinaryOperation" and node.get("operator") in ("&&", "||"):
                complexity += 1
            elif nt == "FunctionCall":
                expr = node.get("expression") or {}
                if expr.get("nodeType") == "Identifier" and expr.get("name") in ("require", "assert"):
                    complexity += 1
            for v in node.values():
                if isinstance(v, dict):
                    stack.append(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            stack.append(item)
        return cls(
            num_functions=num_functions,
            num_payable=num_payable,
            has_external_calls=has_external_calls,
            has_delegatecall=has_delegatecall,
            cyclomatic_complexity=complexity,
        )


def _rank_functions_by_branches(meta: "BytecodeMeta | None") -> tuple[list[str], dict[str, int]]:
    """Return (ranked_fn_names, branches_per_fn).

    Functions are ranked descending by branch count (attack-surface proxy), with
    declaration order breaking ties. When meta is None or empty, returns ([], {}).
    """
    if meta is None or not meta.fn_decls:
        return [], {}

    # Each source line that holds a JUMPI is a branch site; count those per function.
    branch_lines = sorted(meta.source_branches.keys())
    branches_per_fn: dict[str, int] = {}
    for name, (start, end) in meta.fn_line_ranges.items():
        branches_per_fn[name] = sum(1 for ln in branch_lines if start <= ln < end)

    decl_order = {name: i for i, (_, name) in enumerate(meta.fn_decls)}
    ranked = sorted(
        meta.fn_line_ranges.keys(),
        key=lambda n: (-branches_per_fn.get(n, 0), decl_order.get(n, 1 << 30)),
    )
    return ranked, branches_per_fn


def _rank_branch_lines(meta: "BytecodeMeta | None", ranked_fns: list[str]) -> list[int]:
    """Return up to FRONTIER_K source-line branch sites for the frontier channel.

    Branch lines are ranked by the attack-surface rank of the function that
    contains them (hottest function first, matching the heat-map ranking), with
    line number breaking ties — so the channel focuses on the decisions inside
    the highest-fan-out functions. Source lines (not raw JUMPI pcs) are the unit
    because `FuzzResult.branches_this_run` is already source-line deduped.
    """
    if meta is None or not meta.source_branches:
        return []
    fn_rank = {name: i for i, name in enumerate(ranked_fns)}

    def _line_key(ln: int) -> tuple[int, int]:
        owner_rank = 1 << 30
        for name, (start, end) in meta.fn_line_ranges.items():
            if start <= ln < end:
                owner_rank = min(owner_rank, fn_rank.get(name, 1 << 30))
        return (owner_rank, ln)

    return sorted(meta.source_branches.keys(), key=_line_key)[:FRONTIER_K]


class StateEncoder:
    """Encodes dynamic + static contract state into a fixed-dim float vector."""

    NUM_STRATEGIES = 7                                 # full generation roster width
    NUM_MUT_STRATEGIES = 10                            # full mutation roster width
    # Emitted-vector layout (RL Iter 2 + Iter 4 gate + Iter 5 mut block + Iter 6
    # dynamic reshape). The heat-map / frontier accumulators still use FUNC_K /
    # FRONTIER_K, but the emitted vector is compact + dynamic-only. Fixed blocks:
    #   [0-2]  coverage (ratio, velocity, stuck)      → N_COVERAGE
    #   static contract features (GATED, emit_static)  → N_STATIC (default OFF)
    #   revert rate                                    → N_REVERT
    #   dynamic-decision block (frontier sat, corpus
    #     maturity, gen_stall, mut_stall, seed-pool
    #     mean, seed-pool best)                        → DYN_DIMS
    # Two per-strategy reward blocks sit between coverage and the static/revert:
    #   gen block — one dim per ACTIVE generation strategy (`active_gen_mask`)
    #   mut block — one dim per ACTIVE mutation strategy (`active_mut_mask`)
    # (Iter 4: disabled strategies are gated OUT of the state, shrinking the DQN
    # input.) **RL Iter 5:** before this, mutation actions had NO per-strategy
    # reward dim and their reward was mis-credited onto the seed's gen slot — the
    # controller was blind on its mut actions. The mut block gives each active mut
    # strategy its own learnable value signal. Full gen roster (gen mask None) → 7
    # gen dims; mut mask None → 0 mut dims (backward compatible, mut block absent).
    # **RL Iter 6:** static features + the 2 heat-map aggregates left the emitted
    # vector (static gated behind emit_static, default off); gen/mut-stall +
    # seed-pool value dims joined the dynamic block.
    N_COVERAGE = 3
    N_STATIC = 5
    N_REVERT = 1
    # Dynamic-decision tail (RL Iter 6): frontier_sat, corpus_maturity, gen_stall,
    # mut_stall, seed_pool_value_mean, seed_pool_value_best.
    DYN_DIMS = 6
    # ── Per-arm layout (`per_arm_layout`, the shared-per-arm-head sscfuzz) ────────
    # An alternative emitted vector, structured for the factored DQN head
    # (network.py `factored`): a global-context block followed by one contiguous
    # feature tuple per ACTIVE arm (gen slots then mut slots, matching the action
    # table). The head runs ONE shared sub-net over each arm's tuple, so a rarely-
    # tried arm is scored by the rule pooled across all arms — the anti-starvation
    # generalization a flat MLP cannot do. Global block (N_GLOBAL): coverage_ratio,
    # coverage_velocity, frontier_saturation, corpus_maturity, gen_stall, mut_stall,
    # seed_pool_best. (revert / stuck / seed_pool_mean are DROPPED — revert was
    # measured non-contributing; stuck is subsumed by gen/mut_stall; mean co-moves
    # with best.) Per-arm tuple (ARM_FEAT): tanh(avg_reward), tanh(mrew EWMA),
    # dry/DRY_NORM, bug_trace, is_mut (0 gen / 1 mut — lets the one shared sub-net
    # express a gen-vs-mut bias without splitting the head). state_dim = N_GLOBAL +
    # ARM_FEAT·(G+M); for the 5-gen+4-mut sscfuzz roster → 7 + 5·9 = 52.
    N_GLOBAL = 7
    ARM_FEAT = 5
    # Block-layout full-roster default (all 7 gen active, mut block absent, static +
    # bug-trace OFF) = 17. Instances expose the actual width as `self.state_dim`;
    # orchestrator.py syncs RLConfig.state_dim from the instance so a gated roster
    # sizes the network input to match. The `sscfuzz_dqn` method uses the PER-ARM
    # layout above (factored_head) → state_dim 52 for its 5-gen+4-mut roster; the
    # `sscfuzz_esb` bandit uses the block layout (5 gen + 4 mut reward dims + a 9-dim
    # bug-trace block) but discards the vector.
    STATE_DIM = N_COVERAGE + NUM_STRATEGIES + N_REVERT + DYN_DIMS  # = 17

    def __init__(
        self,
        contract_features: ContractFeatures,
        meta: "BytecodeMeta | None" = None,
        active_gen_mask: "list[bool] | None" = None,
        active_mut_mask: "list[bool] | None" = None,
        emit_static: bool = False,
        emit_bug_trace: bool = False,
        bug_trace_decay: float = 0.9,
        marginal_alpha: float = 0.5,
        per_arm_layout: bool = False,
        context_layout: bool = False,
    ):
        self.features = contract_features
        # Context layout (the contextual-bandit `sscfuzz_cb`, LinUCB): emit ONLY the
        # global-context block (+ F1 when emit_static). This is the arm-INDEPENDENT
        # context x for disjoint LinUCB — the per-arm separation is carried by each
        # arm's own θ_a, so the context must not contain per-arm features. Precedence
        # in encode(): context → per-arm → block. See fuzzer/state.py class doc +
        # rl/contextual_bandit.py.
        self._context_layout = context_layout
        # Per-arm layout (the shared-per-arm-head sscfuzz): emit the global-context
        # block + one feature tuple per active arm (see the N_GLOBAL / ARM_FEAT
        # class doc). When on, encode() returns the tuple vector; the bug-trace block
        # is folded into the tuples. The mrew/dry/bug_trace accumulators are
        # maintained under it regardless of emit_bug_trace (their values feed the
        # arm tuples). Off → the block layout (baselines' ablation, sscfuzz_esb).
        self._per_arm_layout = per_arm_layout
        # Whether the 5 static contract features are emitted (RL Iter 6). Default
        # OFF — they're constant within a single-contract run (dead input dims).
        # Flip on for a cross-contract ablation where the net trains across rows.
        self._emit_static = emit_static
        # RL Iter 7 C3 — decaying per-active-strategy "proven bug-finder" trace.
        # Default OFF (SScFuzz-only flag) so baselines / existing callers keep the
        # same state_dim. When ON, a per-active-strategy block (gen then mut, same
        # shape as the reward blocks) carries a recency trace that BUMPS on a novel
        # exploit bank and FADES ×bug_trace_decay each update — durable steering
        # after the one-shot bug reward evaporates, but bounded so it can't
        # tunnel-vision the policy permanently.
        self._emit_bug_trace = emit_bug_trace
        self._bug_trace_decay = float(bug_trace_decay)
        # marginal_alpha = the per-arm reward-EWMA (`mrew`) recency weight, used by
        # the per-arm layout (mrew = α·reward + (1−α)·mrew). The `mrew` (recency) +
        # `dry` (exhaustion) signals — from the retired `sscfuzz_ms` ablation — are
        # now per-arm tuple features maintained under per_arm_layout.
        self._marginal_alpha = float(marginal_alpha)

        # ── Strategy gate (RL Iter 4) ────────────────────────────────────────
        # `active_gen_mask[i]` = is generation strategy i (in GENERATION_STRATEGIES
        # order) active? Disabled strategies never earn reward, so their per-
        # strategy reward slot was a dead input dim — gate them out to shrink the
        # DQN input. `_slot_of` maps a full gen-strategy index → its compact reward
        # slot; disabled indices are absent (update() skips them defensively).
        # mask None ⇒ full roster (backward compatible).
        if active_gen_mask is None:
            active = list(range(self.NUM_STRATEGIES))
        else:
            if len(active_gen_mask) != self.NUM_STRATEGIES:
                raise ValueError(
                    f"active_gen_mask must have length {self.NUM_STRATEGIES}, "
                    f"got {len(active_gen_mask)}"
                )
            active = [i for i, on in enumerate(active_gen_mask) if on]
        self._active_gen: list[int] = active
        self._num_strategies: int = len(active)
        self._slot_of: dict[int, int] = {gi: slot for slot, gi in enumerate(active)}

        # ── Mutation-strategy block (RL Iter 5) ──────────────────────────────
        # `active_mut_mask[i]` = is mutation strategy i (in MUTATION_STRATEGIES
        # order) active? Mirrors the gen gate: each active mut strategy gets its
        # own reward dim, and `_mut_slot_of` maps a full mut index (0-based over
        # MUTATION_STRATEGIES) → its compact slot. mask None ⇒ NO mut block (0
        # dims) — backward compatible with callers that don't opt in (baselines
        # use their own BaselineStateEncoder; older sscfuzz callers keep gen-only).
        if active_mut_mask is None:
            active_mut: list[int] = []
        else:
            if len(active_mut_mask) != self.NUM_MUT_STRATEGIES:
                raise ValueError(
                    f"active_mut_mask must have length {self.NUM_MUT_STRATEGIES}, "
                    f"got {len(active_mut_mask)}"
                )
            active_mut = [i for i, on in enumerate(active_mut_mask) if on]
        self._active_mut: list[int] = active_mut
        self._num_mut_strategies: int = len(active_mut)
        self._mut_slot_of: dict[int, int] = {mi: slot for slot, mi in enumerate(active_mut)}

        # ── Emitted-vector offsets (depend on the active-strategy counts) ────
        # gen reward block, mut reward block, bug-trace block (gated, gen then mut),
        # static (gated), revert, and the dynamic-decision tail (_off_dyn).
        self._off_strategy = self.N_COVERAGE
        self._off_mut = self._off_strategy + self._num_strategies
        # Bug-success trace block (RL Iter 7 C3) — one dim per ACTIVE gen strategy
        # then one per ACTIVE mut strategy, mirroring the two reward blocks. Present
        # only when emit_bug_trace (SScFuzz-only). The mut sub-block starts at
        # _off_bugtrace + _num_strategies.
        self._off_bugtrace = self._off_mut + self._num_mut_strategies
        _bugtrace_width = (
            (self._num_strategies + self._num_mut_strategies) if self._emit_bug_trace else 0
        )
        self._off_static = self._off_bugtrace + _bugtrace_width
        # Static block occupies N_STATIC dims only when emitted (RL Iter 6).
        _static_width = self.N_STATIC if self._emit_static else 0
        self._off_revert = self._off_static + _static_width
        self._off_dyn = self._off_revert + self.N_REVERT
        # Context / per-arm layouts override the emitted width. Both share a
        # global-context block whose width grows by N_STATIC when emit_static feeds
        # the F1 contract features in (one switch, both consumers). The block-layout
        # offsets above are still computed (harmless) but unused by those layouts.
        #   context : the global block ONLY (arm-independent context x for LinUCB).
        #   per-arm : the global block + one ARM_FEAT tuple per active arm (G gen +
        #             M mut); the network's factored head reads n_global / arm_feat /
        #             n_arms to reshape.
        self.n_arms: int = self._num_strategies + self._num_mut_strategies
        _global_w = self.N_GLOBAL + (self.N_STATIC if self._emit_static else 0)
        if self._context_layout:
            self.n_global: int = _global_w
            self.arm_feat: int = 0
            self.state_dim: int = _global_w
        elif self._per_arm_layout:
            self.n_global = _global_w
            self.arm_feat = self.ARM_FEAT
            self.state_dim = _global_w + self.ARM_FEAT * self.n_arms
        else:
            self.n_global = 0
            self.arm_feat = 0
            self.state_dim = self._off_dyn + self.DYN_DIMS

        # ── Per-function heat-map setup ──────────────────────────────────────
        ranked, branches_per_fn = _rank_functions_by_branches(meta)
        # Top FUNC_K-1 functions get their own slot; the rest aggregate into the last slot.
        if len(ranked) <= FUNC_K:
            self._tracked_fns: list[str] = ranked
            self._tail_fns: list[str] = []
        else:
            self._tracked_fns = ranked[: FUNC_K - 1]
            self._tail_fns = ranked[FUNC_K - 1:]
        self._fn_slot: dict[str, int] = {fn: i for i, fn in enumerate(self._tracked_fns)}
        # Per-function branch count (used as denominator when normalizing hits).
        # Falls back to 1 to avoid divide-by-zero.
        self._fn_branches: dict[str, int] = {
            fn: max(1, branches_per_fn.get(fn, 0)) for fn in ranked
        }
        # Cumulative count of distinct iterations that hit each function.
        self._fn_total_hits: dict[str, int] = {fn: 0 for fn in ranked}
        # Snapshot of the last iteration's per-function hit counts (for "current" channel).
        self._last_fn_hits: dict[str, int] = {}
        self._iterations_seen = 0

        # ── Branch-frontier channel setup ────────────────────────────────────
        # The FRONTIER_K hottest source-line branch decisions, plus the set of
        # directions seen at each across the whole run (∅ / {one} / {both}).
        self._frontier_lines: list[int] = _rank_branch_lines(meta, ranked)
        self._branch_dirs_seen: dict[int, set[int]] = {
            ln: set() for ln in self._frontier_lines
        }

        # ── Other dynamic state ──────────────────────────────────────────────
        self._coverage_history: deque[float] = deque(maxlen=10)
        self._gas_history: deque[int] = deque(maxlen=10)
        self._revert_history: deque[bool] = deque(maxlen=10)
        self._strategy_rewards: list[list[float]] = [[] for _ in range(self._num_strategies)]
        # Per-active-mut-strategy reward history (RL Iter 5) — same shape/semantics
        # as `_strategy_rewards` but keyed by compact mut slot.
        self._mut_strategy_rewards: list[list[float]] = [[] for _ in range(self._num_mut_strategies)]
        # Decaying bug-success traces (RL Iter 7 C3) — one float per active gen /
        # mut strategy (compact slot order), bumped on a novel bank, decayed each
        # update. Maintained always; emitted only when _emit_bug_trace.
        self._gen_bug_trace: list[float] = [0.0 for _ in range(self._num_strategies)]
        self._mut_bug_trace: list[float] = [0.0 for _ in range(self._num_mut_strategies)]
        # Recency/exhaustion accumulators — one float per active gen / mut strategy
        # (compact slot order): a reward EWMA (`mrew`) and a consecutive-unproductive
        # pick counter (`dry`). Maintained under per_arm_layout (feed the arm tuples).
        self._gen_mrew: list[float] = [0.0 for _ in range(self._num_strategies)]
        self._mut_mrew: list[float] = [0.0 for _ in range(self._num_mut_strategies)]
        self._gen_dry: list[int] = [0 for _ in range(self._num_strategies)]
        self._mut_dry: list[int] = [0 for _ in range(self._num_mut_strategies)]
        self._stuck_counter = 0
        self._last_coverage = 0.0
        # Corpus fill fraction in [0,1] (RL Iter 3 §3A). Set by the loop before each
        # encode() so the policy can learn *when* to switch generation → mutation:
        # a temporal decision (empty corpus → generate; mature corpus → exploit via
        # mutation) that the flat action space already exposes but couldn't observe.
        self._corpus_maturity = 0.0
        # ── Gen/mut stall counters (RL Iter 6) ───────────────────────────────
        # Iterations since a GENERATION / MUTATION action last found a new
        # bc-branch. Both increment every update(); the matching one resets to 0 on
        # progress. The gen-vs-mut discriminator: a high gen_stall (+ mature corpus)
        # is exactly when mutation should shift the sequence out of the corner.
        self._gen_stall = 0
        self._mut_stall = 0
        # Normalized (÷SEED_VALUE_NORM, clamped) mean/max reward of the current
        # corpus seeds — set by the loop each iter via set_seed_pool (RL Iter 6):
        # answers "are the seeds worth mutating?" independent of the stall signal.
        self._seed_pool_mean = 0.0
        self._seed_pool_best = 0.0

    def set_corpus_maturity(self, frac: float) -> None:
        """Record the corpus fill fraction (0=empty, 1=full) for the next encode()."""
        self._corpus_maturity = float(max(0.0, min(1.0, frac)))

    def set_seed_pool(self, mean_reward: float, best_reward: float) -> None:
        """Record the corpus-seed value stats for the next encode() (RL Iter 6).

        Takes RAW seed rewards (mean and max over `mutator._corpus`), normalizes
        by SEED_VALUE_NORM and clamps to [0,1]. Mirrors `set_corpus_maturity` —
        fed from the loop each iteration before `encode()`.
        """
        self._seed_pool_mean = float(min(1.0, max(0.0, mean_reward / SEED_VALUE_NORM)))
        self._seed_pool_best = float(min(1.0, max(0.0, best_reward / SEED_VALUE_NORM)))

    def encode(self) -> np.ndarray:
        """Return the current `state_dim` float vector.

        Offsets shift with the active-strategy count (RL Iter 4 gate): the
        per-strategy reward block holds one dim per ACTIVE generation strategy,
        so the static / revert / aggregate blocks after it slide accordingly.
        """
        vec = np.zeros(self.state_dim, dtype=np.float32)

        if self._context_layout:
            self._fill_global(vec)   # global block (+F1 when emit_static) only
            return vec
        if self._per_arm_layout:
            return self._encode_per_arm(vec)

        # [0] coverage ratio
        vec[0] = self._coverage_history[-1] if self._coverage_history else 0.0

        # [1] coverage velocity (mean delta over last 10)
        if len(self._coverage_history) >= 2:
            deltas = [
                self._coverage_history[i] - self._coverage_history[i - 1]
                for i in range(1, len(self._coverage_history))
            ]
            vec[1] = float(np.mean(deltas))

        # [2] stuck counter
        vec[2] = min(self._stuck_counter / 100.0, 1.0)

        # avg reward per ACTIVE generation strategy (one dim each, gated roster)
        for slot, rewards in enumerate(self._strategy_rewards):
            vec[self._off_strategy + slot] = float(np.mean(rewards)) if rewards else 0.0

        # avg reward per ACTIVE mutation strategy (RL Iter 5 mut block; empty when
        # active_mut_mask was None → this loop is a no-op and the block is absent)
        for slot, rewards in enumerate(self._mut_strategy_rewards):
            vec[self._off_mut + slot] = float(np.mean(rewards)) if rewards else 0.0

        # decaying bug-success trace per ACTIVE strategy (RL Iter 7 C3) — gen block
        # then mut block, mirroring the reward blocks. Emitted only when enabled.
        if self._emit_bug_trace:
            bt = self._off_bugtrace
            for slot, v in enumerate(self._gen_bug_trace):
                vec[bt + slot] = v
            mbt = bt + self._num_strategies
            for slot, v in enumerate(self._mut_bug_trace):
                vec[mbt + slot] = v

        # static contract features (RL Iter 6: emitted only when emit_static — off
        # by default because they're constant within a single-contract run)
        if self._emit_static:
            st = self._off_static
            vec[st + 0] = min(self.features.num_functions / 20.0, 1.0)
            vec[st + 1] = min(self.features.num_payable / 10.0, 1.0)
            vec[st + 2] = float(self.features.has_external_calls)
            vec[st + 3] = float(self.features.has_delegatecall)
            vec[st + 4] = min(self.features.cyclomatic_complexity / 50.0, 1.0)

        # avg revert rate  (avg-gas dim dropped in the Iter-2 compression)
        vec[self._off_revert] = float(np.mean([float(r) for r in self._revert_history])) if self._revert_history else 0.0

        # ── Dynamic-decision tail (RL Iter 6) ──────────────────────────────────
        # The per-function heat-map accumulators (self._fn_total_hits /
        # self._last_fn_hits) still track full detail but are no longer emitted
        # (the mean-cov / frac-touched aggregates duplicated coverage_ratio). The
        # emitted tail is 6 dynamic dims that all speak to the gen-vs-mut choice.
        dy = self._off_dyn
        # [dy+0] frontier saturation: mean of the per-branch {0.0, 0.5, 1.0} status
        # over the FRONTIER_K tracked branch decisions (where mutation pays).
        if self._frontier_lines:
            sat = 0.0
            for ln in self._frontier_lines:
                n_dirs = len(self._branch_dirs_seen.get(ln) or ())
                sat += 0.0 if n_dirs == 0 else (0.5 if n_dirs == 1 else 1.0)
            vec[dy + 0] = float(sat / len(self._frontier_lines))

        # [dy+1] corpus maturity (RL Iter 3 §3A) — set by the loop each iteration.
        vec[dy + 1] = self._corpus_maturity
        # [dy+2] gen stall, [dy+3] mut stall (RL Iter 6) — iters since a gen/mut
        # action last found a new bc-branch, normalized + clamped.
        vec[dy + 2] = min(self._gen_stall / STALL_NORM, 1.0)
        vec[dy + 3] = min(self._mut_stall / STALL_NORM, 1.0)
        # [dy+4] seed-pool value mean, [dy+5] best (RL Iter 6) — set by the loop.
        vec[dy + 4] = self._seed_pool_mean
        vec[dy + 5] = self._seed_pool_best

        return vec

    def _fill_global(self, vec: np.ndarray) -> int:
        """Fill the shared global-context block; return its width (the arm-tuple base).

        Used by BOTH the per-arm layout (the factored-head sscfuzz) and the context
        layout (the LinUCB sscfuzz_cb). Writes the N_GLOBAL process-context dims, then
        — when emit_static — the N_STATIC F1 contract features, so the single
        emit_static switch feeds F1 into both consumers. Returns N_GLOBAL (+ N_STATIC
        when emit_static) = the effective global width (`self.n_global`).
        """
        # [0] coverage ratio
        vec[0] = self._coverage_history[-1] if self._coverage_history else 0.0
        # [1] coverage velocity (mean delta over last 10)
        if len(self._coverage_history) >= 2:
            deltas = [
                self._coverage_history[i] - self._coverage_history[i - 1]
                for i in range(1, len(self._coverage_history))
            ]
            vec[1] = float(np.mean(deltas))
        # [2] frontier saturation (mean of the per-branch {0, 0.5, 1} status)
        if self._frontier_lines:
            sat = 0.0
            for ln in self._frontier_lines:
                n_dirs = len(self._branch_dirs_seen.get(ln) or ())
                sat += 0.0 if n_dirs == 0 else (0.5 if n_dirs == 1 else 1.0)
            vec[2] = float(sat / len(self._frontier_lines))
        # [3] corpus maturity, [4] gen_stall, [5] mut_stall, [6] seed_pool_best
        vec[3] = self._corpus_maturity
        vec[4] = min(self._gen_stall / STALL_NORM, 1.0)
        vec[5] = min(self._mut_stall / STALL_NORM, 1.0)
        vec[6] = self._seed_pool_best
        n = self.N_GLOBAL
        # F1 static contract features (RL Iter 6, revived for the contextual bandit):
        # appended to the global block when emit_static so a per-arm θ_a (LinUCB) or
        # the factored head can route on contract identity ("has_external_calls ⇒
        # reentrancy arm"). Constant within a single-contract run — dead for a
        # per-contract net, live only across contracts (cross-contract transfer).
        if self._emit_static:
            vec[n + 0] = min(self.features.num_functions / 20.0, 1.0)
            vec[n + 1] = min(self.features.num_payable / 10.0, 1.0)
            vec[n + 2] = float(self.features.has_external_calls)
            vec[n + 3] = float(self.features.has_delegatecall)
            vec[n + 4] = min(self.features.cyclomatic_complexity / 50.0, 1.0)
            n += self.N_STATIC
        return n

    def _encode_per_arm(self, vec: np.ndarray) -> np.ndarray:
        """Emit the per-arm layout: global-context block + ARM_FEAT per active arm.

        Gen arms (compact slot order) come first, then mut arms — matching the
        orchestrator action table so arm i lines up with action index i and the
        factored head's i-th output. See the N_GLOBAL / ARM_FEAT class doc.
        """
        # ── Global context block (N_GLOBAL, + N_STATIC F1 when emit_static) ──────
        base = self._fill_global(vec)
        # ── Per-arm tuples (ARM_FEAT each): tanh(avg), tanh(mrew), dry, bug, is_mut ─
        af = self.ARM_FEAT
        G = self._num_strategies
        for slot in range(G):
            off = base + slot * af
            avg = float(np.mean(self._strategy_rewards[slot])) if self._strategy_rewards[slot] else 0.0
            vec[off + 0] = float(np.tanh(avg / REWARD_TANH_NORM))
            vec[off + 1] = float(np.tanh(self._gen_mrew[slot] / REWARD_TANH_NORM))
            vec[off + 2] = min(self._gen_dry[slot] / DRY_NORM, 1.0)
            vec[off + 3] = self._gen_bug_trace[slot]
            vec[off + 4] = 0.0   # is_mut = 0 for a generation arm
        for mslot in range(self._num_mut_strategies):
            off = base + (G + mslot) * af
            avg = float(np.mean(self._mut_strategy_rewards[mslot])) if self._mut_strategy_rewards[mslot] else 0.0
            vec[off + 0] = float(np.tanh(avg / REWARD_TANH_NORM))
            vec[off + 1] = float(np.tanh(self._mut_mrew[mslot] / REWARD_TANH_NORM))
            vec[off + 2] = min(self._mut_dry[mslot] / DRY_NORM, 1.0)
            vec[off + 3] = self._mut_bug_trace[mslot]
            vec[off + 4] = 1.0   # is_mut = 1 for a mutation arm
        return vec

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # Only the evolving accumulators are persisted; the static per-function /
    # frontier layout is rederived from the bytecode meta on resume (same
    # contract → identical ranking), so restoring these keeps the state vector
    # continuous across an interrupt.
    def checkpoint_state(self) -> dict:
        return {
            "fn_total_hits": dict(self._fn_total_hits),
            "last_fn_hits": dict(self._last_fn_hits),
            "iterations_seen": self._iterations_seen,
            "branch_dirs_seen": {k: set(v) for k, v in self._branch_dirs_seen.items()},
            "coverage_history": list(self._coverage_history),
            "gas_history": list(self._gas_history),
            "revert_history": list(self._revert_history),
            "strategy_rewards": [list(r) for r in self._strategy_rewards],
            "mut_strategy_rewards": [list(r) for r in self._mut_strategy_rewards],
            "gen_bug_trace": list(self._gen_bug_trace),
            "mut_bug_trace": list(self._mut_bug_trace),
            "gen_mrew": list(self._gen_mrew),
            "mut_mrew": list(self._mut_mrew),
            "gen_dry": list(self._gen_dry),
            "mut_dry": list(self._mut_dry),
            "stuck_counter": self._stuck_counter,
            "last_coverage": self._last_coverage,
            "corpus_maturity": self._corpus_maturity,
            "gen_stall": self._gen_stall,
            "mut_stall": self._mut_stall,
            "seed_pool_mean": self._seed_pool_mean,
            "seed_pool_best": self._seed_pool_best,
        }

    def restore_checkpoint_state(self, d: dict) -> None:
        self._fn_total_hits.update(d.get("fn_total_hits", {}))
        self._last_fn_hits = dict(d.get("last_fn_hits", {}))
        self._iterations_seen = d.get("iterations_seen", 0)
        for k, v in d.get("branch_dirs_seen", {}).items():
            if k in self._branch_dirs_seen:
                self._branch_dirs_seen[k] = set(v)
        self._coverage_history.extend(d.get("coverage_history", []))
        self._gas_history.extend(d.get("gas_history", []))
        self._revert_history.extend(d.get("revert_history", []))
        sr = d.get("strategy_rewards")
        if sr and len(sr) == len(self._strategy_rewards):
            self._strategy_rewards = [list(r) for r in sr]
        msr = d.get("mut_strategy_rewards")
        if msr and len(msr) == len(self._mut_strategy_rewards):
            self._mut_strategy_rewards = [list(r) for r in msr]
        gbt = d.get("gen_bug_trace")
        if gbt and len(gbt) == len(self._gen_bug_trace):
            self._gen_bug_trace = [float(v) for v in gbt]
        mbt = d.get("mut_bug_trace")
        if mbt and len(mbt) == len(self._mut_bug_trace):
            self._mut_bug_trace = [float(v) for v in mbt]
        gmr = d.get("gen_mrew")
        if gmr and len(gmr) == len(self._gen_mrew):
            self._gen_mrew = [float(v) for v in gmr]
        mmr = d.get("mut_mrew")
        if mmr and len(mmr) == len(self._mut_mrew):
            self._mut_mrew = [float(v) for v in mmr]
        gdr = d.get("gen_dry")
        if gdr and len(gdr) == len(self._gen_dry):
            self._gen_dry = [int(v) for v in gdr]
        mdr = d.get("mut_dry")
        if mdr and len(mdr) == len(self._mut_dry):
            self._mut_dry = [int(v) for v in mdr]
        self._stuck_counter = d.get("stuck_counter", 0)
        self._last_coverage = d.get("last_coverage", 0.0)
        self._corpus_maturity = d.get("corpus_maturity", 0.0)
        self._gen_stall = d.get("gen_stall", 0)
        self._mut_stall = d.get("mut_stall", 0)
        self._seed_pool_mean = d.get("seed_pool_mean", 0.0)
        self._seed_pool_best = d.get("seed_pool_best", 0.0)

    def update(
        self,
        strategy_idx: int,
        result: FuzzResult,
        reward: float,
        mut_idx: int | None = None,
        banked_exploit: bool = False,
    ) -> None:
        """Update dynamic state after a fuzz run.

        `strategy_idx` is a full GENERATION_STRATEGIES index (0-6). Under the
        Iter-4 gate the gen reward vector holds only ACTIVE strategies, so map the
        full index → compact slot; a disabled index (shouldn't occur — disabled
        strategies are never selected and produce no seeds) is skipped.

        `mut_idx` (RL Iter 5) — full MUTATION_STRATEGIES index (0-9) when this run
        was a mutation, else None. When set, the reward credits the MUTATION slot
        (not the gen slot): in mutation mode `strategy_idx` is the *seed's* gen
        strategy, and crediting it would mis-attribute the mutation's outcome onto
        generation signal (the pre-Iter-5 bug). So a mut run updates only its mut
        slot; a gen run updates only its gen slot.

        `banked_exploit` (RL Iter 7 C3) — True iff this run banked a NOVEL exploit
        path (result.new_exploit_path==1). The per-strategy bug-success trace decays
        every update and BUMPS the slot for THIS action (routed via mut_idx /
        strategy_idx, same as the reward) on a bank — a durable, fading foothold.
        """
        self._coverage_history.append(result.coverage)
        self._gas_history.append(result.gas_used)
        self._revert_history.append(result.reverted)

        if mut_idx is not None:
            mslot = self._mut_slot_of.get(mut_idx)
            if mslot is not None:
                self._mut_strategy_rewards[mslot].append(reward)
                if len(self._mut_strategy_rewards[mslot]) > 50:
                    self._mut_strategy_rewards[mslot] = self._mut_strategy_rewards[mslot][-50:]
        else:
            slot = self._slot_of.get(strategy_idx)
            if slot is not None:
                self._strategy_rewards[slot].append(reward)
                # Bound per-strategy reward history.
                if len(self._strategy_rewards[slot]) > 50:
                    self._strategy_rewards[slot] = self._strategy_rewards[slot][-50:]

        # Bug-success trace (RL Iter 7 C3): fade every update, bump this action's
        # slot on a novel bank (routed to the mut slot in mut mode, else gen slot).
        # Maintained under the per-arm layout too (it feeds each arm's tuple).
        if self._emit_bug_trace or self._per_arm_layout:
            rho = self._bug_trace_decay
            self._gen_bug_trace = [v * rho for v in self._gen_bug_trace]
            self._mut_bug_trace = [v * rho for v in self._mut_bug_trace]
            if banked_exploit:
                if mut_idx is not None:
                    mslot = self._mut_slot_of.get(mut_idx)
                    if mslot is not None:
                        self._mut_bug_trace[mslot] = min(
                            1.0, self._mut_bug_trace[mslot] + BUG_TRACE_BUMP
                        )
                else:
                    slot = self._slot_of.get(strategy_idx)
                    if slot is not None:
                        self._gen_bug_trace[slot] = min(
                            1.0, self._gen_bug_trace[slot] + BUG_TRACE_BUMP
                        )

        # Recency/exhaustion accumulators (per-arm layout): update ONLY this action's
        # slot (routed via mut_idx / strategy_idx, same as the reward). mrew = reward
        # EWMA (recency); dry = consecutive unproductive picks (reset on a new
        # bc-branch OR a banked exploit, else +1). They feed each arm's tuple.
        if self._per_arm_layout:
            a = self._marginal_alpha
            productive = result.new_bc_branches > 0 or banked_exploit
            if mut_idx is not None:
                mslot = self._mut_slot_of.get(mut_idx)
                if mslot is not None:
                    self._mut_mrew[mslot] = a * reward + (1.0 - a) * self._mut_mrew[mslot]
                    self._mut_dry[mslot] = 0 if productive else self._mut_dry[mslot] + 1
            else:
                slot = self._slot_of.get(strategy_idx)
                if slot is not None:
                    self._gen_mrew[slot] = a * reward + (1.0 - a) * self._gen_mrew[slot]
                    self._gen_dry[slot] = 0 if productive else self._gen_dry[slot] + 1

        # Stuck detection — no coverage gain.
        if result.coverage <= self._last_coverage:
            self._stuck_counter += 1
        else:
            self._stuck_counter = 0
        self._last_coverage = result.coverage

        # Gen/mut stall counters (RL Iter 6): both advance every iteration; the
        # counter matching THIS action's mode resets when it found a new bc-branch.
        # A high gen_stall means generation has gone stale (mutation's cue), and
        # vice versa — the gen-vs-mut discriminator the emitted vector exposes.
        self._gen_stall += 1
        self._mut_stall += 1
        if result.new_bc_branches > 0:
            if mut_idx is not None:
                self._mut_stall = 0
            else:
                self._gen_stall = 0

        # Per-function heat-map: bump cumulative hit count for any function touched
        # this iter, and snapshot the per-iteration hits for the "current" channel.
        self._last_fn_hits = dict(result.function_hit_counts or {})
        for fn in result.functions_this_run or ():
            if fn in self._fn_total_hits:
                self._fn_total_hits[fn] += 1
        self._iterations_seen += 1

        # Branch-frontier: accumulate the directions seen at each tracked branch
        # site. branches_this_run holds source-level (line, direction) pairs.
        for line, direction in result.branches_this_run or ():
            dirs = self._branch_dirs_seen.get(line)
            if dirs is not None:
                dirs.add(direction)
