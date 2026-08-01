"""Corpus-based mutation engine for the gen×mut hybrid fuzzer."""

from __future__ import annotations

import copy
import json
import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import logging

from ..config import RLConfig
from .arg_sampling import coerce_scalar
from .sol_interface import interface_eligible
from ..llm.agent import FuzzInput, TokenUsage, _LLMClient, _truncate_prompt
from ..llm.prompts import MUT_PROMPT_TMPL, SYSTEM_PROMPT
from ..llm.prompts.common import ARG_ENCODING_BLOCK

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..config import LLMConfig

# Generation strategy → eligible fallback mutation strategies (ABI-level, always preserve validity)
_MUTATION_STRATEGIES_FOR: dict[str, list[str]] = {
    "reentrancy_probe":     ["call_insert", "call_shuffle", "reentry_depth"],
    "arithmetic_probe":     ["value_perturb", "arg_boundary"],
    "access_control_probe": ["caller_swap", "arg_shuffle", "call_insert"],
    "price_oracle_probe":   ["value_perturb", "arg_shuffle", "call_insert", "call_shuffle"],
    "logic_error_probe":    ["caller_swap", "arg_shuffle", "call_shuffle", "call_insert", "call_delete"],
    "boundary_values":      ["value_perturb", "arg_boundary"],
    "exploration":          [
        "value_perturb", "arg_boundary", "arg_address", "arg_shuffle", "caller_swap",
        "call_insert", "call_delete", "call_shuffle", "reentry_depth", "call_swap",
    ],
}

# Boundary values for arg_boundary mutation_strategy
_UINT_BOUNDARIES: list[int] = [
    0, 1,
    2**8 - 1,  2**8,
    2**16 - 1, 2**16,
    2**32 - 1, 2**32,
    2**64 - 1, 2**64,
    2**128 - 1, 2**128,
    2**255 - 1, 2**256 - 1,
]

_VALUE_MULTIPLIERS: list[float] = [0.0, 0.5, 1.5, 2.0, 10.0, 0.1]

_BASE_CALLERS: list[str] = ["attacker_address"]
_REENTRY_CALLERS: list[str] = ["attacker_address"]

# Default address-arg redirect targets for arg_address / arg_shuffle (all resolve
# in FoundryFuzzer._ADDR_ALIASES or as a raw 0x literal). attacker_address =
# self-promotion / mint-to-self; target_address = the contract itself (ERC404
# transfer-to-token mint); zero address = burn / unguarded sink. Used only when
# the orchestrator does not supply a mode-aware pool (e.g. in unit tests); the
# live path threads fuzzer.arg_sampling.build_address_pool via `address_pool`.
_ARG_ADDR_ALIASES: list[str] = [
    "attacker_address", "target_address",
    "0x0000000000000000000000000000000000000000",
]


@dataclass
class CorpusEntry:
    """A fuzzing run stored in the corpus for future mutation.

    `bc_branches_this_run` is the bytecode-level (jumpi_pc, direction) set used
    for corpus curation — Group A (AFL-favored minimal coverer) ranks by which
    branches an entry is the leanest coverer of. (In the legacy/baseline reward
    path it is also the `_novelty` baseline when mutating this seed; the SScFuzz
    two-tier path (RL Iter 7) uses per-strategy coverage instead — see reward.py.)

    `bug_signal_found` marks an entry as an exploit witness (Group B candidate).
    `high_bug_signal_found` (RL Iter 7 C6) marks it as a HIGH-tier (proved net
    profit/loss) exploit — Group B now EXCLUDES these (a banked high-signal exploit
    is path-gated → its re-mutation yields ~nothing), keeping only the WEAK-signal
    (heuristic-tier) near-misses whose right mutation could tip them into a real hit.
    `num_calls` is the executable call count (excluding reentrancy setup
    sentinels) — the length signal Group A uses to evict padded clones.
    `reward` is kept for logging/tiebreak only; it no longer drives curation.
    """
    fuzz_input: FuzzInput
    reward: float
    strategy: str
    bc_branches_this_run: frozenset = field(default_factory=frozenset)
    iteration: int = 0
    bug_signal_found: bool = False
    high_bug_signal_found: bool = False
    num_calls: int = 0

    def __post_init__(self) -> None:
        # Auto-derive call length (setup sentinels don't count toward "shortest").
        if not self.num_calls:
            self.num_calls = sum(
                1 for c in self.fuzz_input.calls
                if c[0] != "atk.setReentrantCall"
            )


class LLMMutator:
    """Corpus + LLM-backed mutator actor.

    Manages a bounded corpus of CorpusEntry objects and provides two paths:
      llm_mutate  — LLM applies a named mutation strategy to a seed (primary path)
      mutate      — ABI-level mutation strategy applied directly (fallback / no-LLM)

    Mutation strategies preserve ABI validity by construction:
      value_perturb  — scale ETH value on payable calls
      arg_boundary   — set numeric args to edge/boundary values
      caller_swap    — swap caller between valid aliases for the strategy
      call_insert    — insert a new ABI-valid call at a random position
      call_delete    — remove a random non-setup call (keeps at least 1)
      call_shuffle   — reorder calls (preserves atk.setReentrantCall at head)
      reentry_depth  — adjust max_count in setReentrantCall config
      call_swap      — substitute one call with a different ABI function (same length)
      arg_shuffle    — rewrite one argument of ANY type with an edge value (generalizes arg_address)

    Corpus invariant: at most `corpus_top_coverage + corpus_top_reward` entries,
    forming the union of two groups:
      Group A (k_cov) — AFL-favored minimal coverer: keep the entries that are
                        the shortest (then earliest) coverer of the most
                        branches. Padded clones lose every per-branch length
                        tiebreak to their lean core and get culled.
      Group B (k_bug) — weak-signal bug witnesses (RL Iter 7 C6): leanest
                        representative of each distinct attack path (Jaccard<0.9)
                        among HEURISTIC-tier near-misses (bug_signal_found AND NOT
                        high_bug_signal_found) — the near-miss→hit conversion is the
                        higher-value use of the mutation budget than re-mutating an
                        already-banked (path-gated) high-signal exploit. Bug "type"
                        is irrelevant for selection.
    Seed selection is uniform random over this union.
    """

    def __init__(
        self,
        config: RLConfig,
        llm_config: LLMConfig | None = None,
        abi: list[dict] | None = None,
        initial_balance_native: int = 10,
        shared_llm=None,
        address_pool: list[str] | None = None,
    ):
        self.config = config
        self._corpus: list[CorpusEntry] = []
        # Mode-aware address-redirect targets for arg_address / arg_shuffle (built
        # by the orchestrator via fuzzer.arg_sampling.build_address_pool). Falls
        # back to the inline default when the caller supplies none (unit tests).
        self._arg_addr_aliases: list[str] = list(address_pool) if address_pool else list(_ARG_ADDR_ALIASES)

        # Build ABI lookup tables (mirrors FoundryFuzzer construction)
        self._abi_types: dict[str, list[str]] = {}
        self._abi_payable: set[str] = set()
        if abi:
            # Class A: mutation-inserted calls must be interface-callable too — drop
            # tuple-typed functions (single source of truth in sol_interface).
            for item in interface_eligible(abi):
                if item.get("type") == "function":
                    name = item["name"]
                    self._abi_types[name] = [
                        inp.get("type", "") for inp in item.get("inputs", [])
                    ]
                    if item.get("stateMutability") == "payable":
                        self._abi_payable.add(name)

        self._fn_names: list[str] = list(self._abi_types.keys())
        if shared_llm is not None:
            self._llm: _LLMClient | None = shared_llm
        elif llm_config is not None:
            self._llm = _LLMClient(llm_config, initial_balance_native)
        else:
            self._llm = None

    # ── LLM mutation ──────────────────────────────────────────────────────────

    @property
    def token_stats(self) -> TokenUsage | None:
        return self._llm.token_stats if self._llm else None

    # ── Iteration-level checkpointing (see fuzz/checkpoint.py) ─────────────────
    # The curated corpus is the only evolving state here (the ABI tables + LLM
    # client are rebuilt / shared on resume). CorpusEntry (FuzzInput + frozensets)
    # is picklable, so torch.save handles it directly.
    def checkpoint_state(self) -> dict:
        return {"corpus": self._corpus}

    def restore_checkpoint_state(self, d: dict) -> None:
        self._corpus = list(d.get("corpus", []))

    def format_history_rich(self, key: str | None = None) -> str | None:
        return self._llm.format_history_rich(key) if self._llm else None

    def record_run(
        self,
        fuzz_input: FuzzInput,
        reward: float,
        forge_status: str,
        raw_reason: str = "",
        new_branches: int = 0,
        decoded_logs: list[str] = (),
        strategy: str = "",
        mode: str = "",
    ) -> None:
        if self._llm:
            self._llm.record_run(fuzz_input, reward, forge_status, raw_reason, new_branches, decoded_logs, strategy, mode)

    def llm_mutate(
        self,
        seed: CorpusEntry,
        mutation_strategy: str,
        contract_source: str,
        contract_abi: list[dict],
        n: int = 1,
        debug: bool = False,
    ) -> list[FuzzInput]:
        """Apply *mutation_strategy* to *seed* via LLM; falls back to ABI-level mutation on failure."""
        if self._llm is None:
            return [self.mutate(seed, mutation_strategy)]

        from ..llm.strategies import MUTATION_STRATEGY_PROMPTS

        self._llm.setup_abi(contract_abi)
        prompt_def = MUTATION_STRATEGY_PROMPTS[mutation_strategy]
        context = self._llm.build_contract_context(contract_source, contract_abi)
        caller_list = ", ".join(f'"{c}"' for c in prompt_def["caller_hints"])
        extend_section = (
            f"\n**Extra notes:** {prompt_def['extend_hints']}"
            if prompt_def["extend_hints"]
            else ""
        )
        # Declared external contracts + $ret chaining rule ("" when target-only),
        # so a mutation can introduce / preserve external calls in the seed.
        extend_section += self._llm.external_prompt_section()

        history = self._llm.format_history(mutation_strategy)
        max_seq = self._llm.config.max_calls_per_item
        user_prompt = MUT_PROMPT_TMPL.format(
            context=context,
            n=n,
            seed_strategy=seed.strategy,
            mutation_strategy=mutation_strategy,
            seed_reward=seed.reward,
            initial_balance=self._llm.initial_balance_native,
            max_calls_per_item=max_seq,
            goal=prompt_def["goal"],
            technique=prompt_def["technique"],
            value_hints=prompt_def["value_hints"],
            caller_list=caller_list,
            extend_section=extend_section,
            arg_encoding=ARG_ENCODING_BLOCK,
            seed_json=json.dumps(seed.fuzz_input.to_dict(), indent=2),
            history=history,
        )

        if debug:
            logger.debug("LLM system prompt:\n%s", SYSTEM_PROMPT)
            logger.debug("LLM mode: MUTATE  mutation_strategy=%s  seed_strategy=%s", mutation_strategy, seed.strategy)
            logger.debug("LLM user prompt:\n%s", _truncate_prompt(user_prompt))

        # Reset fallback marker — set to a reason string iff we exhaust retries.
        # orchestrator.py reads this after the call to populate `fallback_reason` in the run log.
        self._llm.last_fallback_reason = None
        max_retries = self._llm.config.llm_retries
        last_err = "unknown"
        for attempt in range(1, max_retries + 1):
            try:
                raw = self._llm.complete(user_prompt, cache_prefix=context)
                if debug:
                    logger.debug("LLM response:\n%s", raw)
                extracted = _LLMClient.extract_json(raw)
                items = json.loads(extracted)
                if not isinstance(items, list):
                    items = [items]
                items = _LLMClient.normalize_items(items)
                if not items:
                    raise ValueError("empty list")
                results = [
                    FuzzInput.from_dict(item)
                    for item in items[:n]
                    if isinstance(item, dict)
                ]
                if not results:
                    raise ValueError("no usable items after normalization")
                for fi in results:
                    if len(fi.calls) > max_seq:
                        logger.warning(
                            "LLM generated %d calls (max %d) — truncating", len(fi.calls), max_seq
                        )
                        fi.calls = fi.calls[:max_seq]
                return results
            except Exception as e:
                # Log the raw model output that failed to parse (see generator.py
                # for rationale) so grammar-disable / truncation is diagnosable
                # without --debug.
                raw_preview = (self._llm.last_response or "")[:200]
                if attempt < max_retries:
                    logger.warning(
                        "llm_mutate() attempt %d/%d failed (%s: %s) — retrying. raw: %r",
                        attempt, max_retries, type(e).__name__, e, raw_preview,
                    )
                else:
                    last_err = f"{type(e).__name__}: {e} | raw: {raw_preview!r}"
        logger.warning(
            "⚠ LLM llm_mutate() exhausted %d retries (mutation_strategy=%s seed_strategy=%s) — "
            "falling back to ABI-level mutation_strategy (last error: %s). LLM-guided mutation "
            "disabled this iteration; check llama-cpp server logs and grammar validity.",
            max_retries, mutation_strategy, seed.strategy, last_err,
        )
        self._llm.last_fallback_reason = f"llm_exhausted: {last_err}"
        return [self.mutate(seed, mutation_strategy)]

    # ── Corpus management ─────────────────────────────────────────────────────

    def add(self, entry: CorpusEntry) -> None:
        """Add entry and prune to Group A (favored coverer) ∪ Group B (witnesses)."""
        self._corpus.append(entry)
        keep_a = self._group_a(self._corpus, self.config.corpus_top_coverage)
        keep_b = self._group_b(self._corpus, self.config.corpus_top_reward)  # k_bug
        keep = {id(e) for e in keep_a} | {id(e) for e in keep_b}
        self._corpus = [e for e in self._corpus if id(e) in keep]

    @staticmethod
    def _group_a(corpus: list[CorpusEntry], k: int) -> list[CorpusEntry]:
        """AFL-favored minimal coverer: keep the top-k entries that are the
        leanest coverer of the most branches.

        For each branch, the favored coverer is the entry hitting it with the
        fewest calls (earliest iteration breaks ties). An entry's score is how
        many branches it's favored for; a padded clone covering the same
        branches as its lean core loses every tiebreak ⇒ score 0 ⇒ culled.
        """
        best: dict = {}  # branch -> leanest entry covering it
        for e in corpus:
            for b in e.bc_branches_this_run:
                cur = best.get(b)
                if cur is None or (e.num_calls, e.iteration) < (cur.num_calls, cur.iteration):
                    best[b] = e
        from collections import Counter
        favored = Counter(id(best[b]) for b in best)
        cands = [e for e in corpus if favored.get(id(e), 0) > 0]
        cands.sort(key=lambda e: (-favored[id(e)], e.num_calls, e.iteration))
        return cands[:k]

    @staticmethod
    def _group_b(corpus: list[CorpusEntry], k: int) -> list[CorpusEntry]:
        """Weak-signal bug-witness group (RL Iter 7 C6): leanest representative of
        each distinct attack path (Jaccard<0.9) among HEURISTIC-tier near-misses,
        up to k paths.

        Admits `bug_signal_found AND NOT high_bug_signal_found` — a suspicious
        balance move (heuristic tier) the right mutation could push over the line
        into a real exploit. EXCLUDES high-signal (`high_bug_signal_found`) exploits:
        those are already banked (path-gated → re-mutation scores ~0), so they carry
        no mutation value as seeds (they're still recorded as found_bugs). Sorted
        leanest-first; a witness ≥0.9 similar to one already kept is the same attack.
        """
        from .paths import is_distinct_path

        eligible = [
            e for e in corpus if e.bug_signal_found and not e.high_bug_signal_found
        ]
        eligible.sort(key=lambda e: (e.num_calls, e.iteration, -len(e.bc_branches_this_run)))
        selected: list[CorpusEntry] = []
        for e in eligible:
            if is_distinct_path(
                e.bc_branches_this_run, [s.bc_branches_this_run for s in selected]
            ):
                selected.append(e)
                if len(selected) >= k:
                    break
        return selected

    def __len__(self) -> int:
        return len(self._corpus)

    def sample_seed(self, strategy: str | None = None) -> CorpusEntry | None:
        """Return one corpus entry uniformly at random; None if corpus empty.

        The `strategy` parameter is accepted for call-site compatibility but
        ignored — the corpus is already curated to Group A (favored coverer) ∪
        Group B (exploit witnesses), so every entry is a high-value seed
        regardless of its origin strategy.
        """
        _ = strategy
        if not self._corpus:
            return None
        return random.choice(self._corpus)

    # ── Mutation dispatcher ───────────────────────────────────────────────────

    def mutate(self, seed: CorpusEntry, mutation_strategy: str) -> FuzzInput:
        """Apply the named mutation strategy to the seed and return a new FuzzInput.

        Always deep-copies the seed's calls before mutation so the corpus entry
        is never modified in-place.  The seed's (generation) strategy is forwarded
        to the mutation methods that need it (e.g. caller_swap uses it to pick
        valid aliases).
        """
        method = getattr(self, f"_mut_{mutation_strategy}", None)
        if method is None:
            # Unknown mutation strategy — fall back to a random eligible one for the seed's strategy
            eligible = _MUTATION_STRATEGIES_FOR.get(seed.strategy, list(_MUTATION_STRATEGIES_FOR["exploration"]))
            method = getattr(self, f"_mut_{random.choice(eligible)}")
        new_calls = method(copy.deepcopy(seed.fuzz_input.calls), seed.strategy)
        return FuzzInput(
            calls=new_calls,
            description=f"mut:{mutation_strategy}@iter{seed.iteration}",
        )

    # ── Mutation strategies (ABI-level) ─────────────────────────────────────────

    def _mut_value_perturb(self, calls: list, strategy: str) -> list:
        """Scale ETH value of a random payable call by a random multiplier."""
        payable_indices = [
            i for i, c in enumerate(calls)
            if c[0] != "atk.setReentrantCall" and c[0] in self._abi_payable
        ]
        if not payable_indices:
            return calls
        idx = random.choice(payable_indices)
        call = calls[idx]
        raw = call[2] if len(call) > 2 else 0
        try:
            current = int(str(raw), 0) if raw else 0
        except (ValueError, TypeError):
            current = 0
        if current == 0:
            current = 10 ** 18  # default to 1 ETH when currently 0
        new_value = max(0, int(current * random.choice(_VALUE_MULTIPLIERS)))
        calls[idx] = [
            call[0],
            call[1] if len(call) > 1 else [],
            new_value,
            call[3] if len(call) > 3 else "attacker_address",
        ]
        return calls

    def _mut_arg_boundary(self, calls: list, strategy: str) -> list:
        """Replace one argument with a boundary (numeric) or degenerate (array/bytes) value.

        Address args are left untouched — redirecting those is _mut_arg_address's job.
        """
        mutable = [
            i for i, c in enumerate(calls)
            if c[0] != "atk.setReentrantCall"
            and isinstance(c[1] if len(c) > 1 else None, list)
            and len(c[1]) > 0
        ]
        if not mutable:
            return calls
        call_idx = random.choice(mutable)
        call = calls[call_idx]
        args = list(call[1])
        arg_idx = random.randrange(len(args))
        arg_types = self._abi_types.get(call[0], [])
        sol_type = arg_types[arg_idx] if arg_idx < len(arg_types) else ""
        if sol_type.endswith("[]"):
            args[arg_idx] = []  # degenerate empty collection (length-underflow / sig-array bypass)
        elif sol_type == "bytes":
            args[arg_idx] = "0x"  # empty bytes — bypasses length-naive signature/proof checks
        elif "address" not in sol_type:
            # Tier-1: mask/clamp the boundary to the slot's real width (a bytes32
            # slot gets a full-width literal, a uint16 stays in range).
            args[arg_idx] = coerce_scalar(sol_type, random.choice(_UINT_BOUNDARIES))
        calls[call_idx] = [
            call[0], args,
            call[2] if len(call) > 2 else 0,
            call[3] if len(call) > 3 else "attacker_address",
        ]
        return calls

    def _mut_arg_address(self, calls: list, strategy: str) -> list:
        """Redirect one address-typed argument to a different alias.

        Targets self-promotion (setOwner/addMinter(attacker)), mint-to-self
        (mint(attacker, …)), and the contract-as-recipient case (ERC404 transfer
        to target_address). Numeric args and ETH values are preserved.
        """
        candidates: list[tuple[int, int]] = []
        for i, c in enumerate(calls):
            if c[0] == "atk.setReentrantCall":
                continue
            args = c[1] if len(c) > 1 else None
            if not isinstance(args, list):
                continue
            arg_types = self._abi_types.get(c[0], [])
            for j in range(len(args)):
                if (arg_types[j] if j < len(arg_types) else "") == "address":
                    candidates.append((i, j))
        if not candidates:
            return calls
        call_idx, arg_idx = random.choice(candidates)
        call = calls[call_idx]
        args = list(call[1])
        current = str(args[arg_idx])
        others = [a for a in self._arg_addr_aliases if a != current]
        args[arg_idx] = random.choice(others) if others else self._arg_addr_aliases[0]
        calls[call_idx] = [
            call[0], args,
            call[2] if len(call) > 2 else 0,
            call[3] if len(call) > 3 else "attacker_address",
        ]
        return calls

    def _mut_arg_shuffle(self, calls: list, strategy: str) -> list:
        """Rewrite ONE argument of ANY type with a plausible alternative/edge value.

        A generalization of arg_address (which only touched address args): here the
        chosen argument is mutated by its Solidity type — address → a different
        alias (self-promotion / mint-to-self / contract-as-recipient / zero sink);
        numeric → a uint boundary; bytes → empty bytes; array → a degenerate empty
        collection; bool → flipped. So a single operator covers the value-edge
        surface of arg_address + arg_boundary across every argument kind. ETH value
        and caller are preserved; setup entries are never touched.
        """
        mutable = [
            i for i, c in enumerate(calls)
            if c[0] != "atk.setReentrantCall"
            and isinstance(c[1] if len(c) > 1 else None, list)
            and len(c[1]) > 0
        ]
        if not mutable:
            return calls
        call_idx = random.choice(mutable)
        call = calls[call_idx]
        args = list(call[1])
        arg_idx = random.randrange(len(args))
        arg_types = self._abi_types.get(call[0], [])
        sol_type = arg_types[arg_idx] if arg_idx < len(arg_types) else ""
        if sol_type.endswith("[]"):
            args[arg_idx] = []  # degenerate empty collection
        elif sol_type == "bytes":
            args[arg_idx] = "0x"  # empty bytes — bypasses length-naive checks
        elif sol_type == "bool":
            cur = args[arg_idx]
            args[arg_idx] = not (cur is True or str(cur).lower() in ("true", "1", "0x1"))
        elif "address" in sol_type:
            current = str(args[arg_idx])
            others = [a for a in self._arg_addr_aliases if a != current]
            args[arg_idx] = random.choice(others) if others else self._arg_addr_aliases[0]
        else:  # numeric (uint*/int*) or unknown → width-correct boundary sweep
            args[arg_idx] = coerce_scalar(sol_type, random.choice(_UINT_BOUNDARIES))
        calls[call_idx] = [
            call[0], args,
            call[2] if len(call) > 2 else 0,
            call[3] if len(call) > 3 else "attacker_address",
        ]
        return calls

    def _mut_caller_swap(self, calls: list, strategy: str) -> list:
        """Swap the caller of a random call to another valid alias.

        With a single unified attacker identity (attacker_address) the caller pool
        has one entry, so `len(valid) < 2` short-circuits to a no-op: there is no
        second caller to swap to. Kept as a stable action slot (RL action 9).
        """
        valid = _REENTRY_CALLERS if strategy == "reentrancy_probe" else _BASE_CALLERS
        if len(valid) < 2:
            return calls
        regular = [i for i, c in enumerate(calls) if c[0] != "atk.setReentrantCall"]
        if not regular:
            return calls
        idx = random.choice(regular)
        call = calls[idx]
        current = call[3] if len(call) > 3 else "attacker_address"
        others = [v for v in valid if v != current]
        if others:
            calls[idx] = [
                call[0],
                call[1] if len(call) > 1 else [],
                call[2] if len(call) > 2 else 0,
                random.choice(others),
            ]
        return calls

    def _mut_call_insert(self, calls: list, strategy: str) -> list:
        """Insert a new ABI-valid call at a random position after any setup entries."""
        if not self._fn_names:
            return calls
        max_seq = self._llm.config.max_calls_per_item if self._llm else 8
        if len(calls) >= max_seq:
            return calls
        fn = random.choice(self._fn_names)
        arg_types = self._abi_types.get(fn, [])
        args = [self._random_arg(t) for t in arg_types]
        is_payable = fn in self._abi_payable
        value = random.choice([0, 10 ** 18, 2 * 10 ** 18]) if is_payable else 0
        valid = _REENTRY_CALLERS if strategy == "reentrancy_probe" else _BASE_CALLERS
        new_call = [fn, args, value, random.choice(valid)]

        # Insert after reentrancy setup entries, if any
        setup_end = next(
            (i + 1 for i, c in enumerate(calls) if c[0] == "atk.setReentrantCall"),
            0,
        )
        calls.insert(random.randint(setup_end, len(calls)), new_call)
        return calls

    def _mut_call_delete(self, calls: list, strategy: str) -> list:
        """Remove one random non-setup call; always keep at least one regular call."""
        regular = [i for i, c in enumerate(calls) if c[0] != "atk.setReentrantCall"]
        if len(regular) <= 1:
            return calls
        calls.pop(random.choice(regular))
        return calls

    def _mut_call_shuffle(self, calls: list, strategy: str) -> list:
        """Shuffle regular calls while keeping setup entries at the head."""
        setup = [c for c in calls if c[0] == "atk.setReentrantCall"]
        regular = [c for c in calls if c[0] != "atk.setReentrantCall"]
        random.shuffle(regular)
        return setup + regular

    def _mut_reentry_depth(self, calls: list, strategy: str) -> list:
        """Adjust max_count in a atk.setReentrantCall entry."""
        for i, call in enumerate(calls):
            if call[0] == "atk.setReentrantCall" and isinstance(call[1], dict):
                cfg = dict(call[1])
                current = int(cfg.get("max_count", 3))
                delta = random.choice([-2, -1, 1, 2, 3])
                # Capped at 5 (see foundry.MAX_REENTRY_COUNT) to bound the trace.
                cfg["max_count"] = max(1, min(5, current + delta))
                calls[i] = [
                    call[0], cfg,
                    call[2] if len(call) > 2 else "0x0",
                    call[3] if len(call) > 3 else "attacker_address",
                ]
                break
        return calls

    def _mut_call_swap(self, calls: list, strategy: str) -> list:
        """Substitute one non-setup call with a call to a DIFFERENT ABI function.

        Keeps the sequence length and the call's position (distinct from
        call_insert=add / call_delete=remove) — no other kept mutation changes the
        *function* itself. RL Iter 3 gated candidate: disabled by default and
        enabled only if it clears the standard bar (>0 unbiased yield / ≥1 unique
        solve) in the measurement experiment.
        """
        if not self._fn_names:
            return calls
        regular = [i for i, c in enumerate(calls) if c[0] != "atk.setReentrantCall"]
        if not regular:
            return calls
        idx = random.choice(regular)
        existing = calls[idx][0]
        alternatives = [f for f in self._fn_names if f != existing]
        if not alternatives:
            return calls
        fn = random.choice(alternatives)
        arg_types = self._abi_types.get(fn, [])
        args = [self._random_arg(t) for t in arg_types]
        is_payable = fn in self._abi_payable
        # Keep the original ETH value on a non-payable swap; sample one for payable.
        orig_value = calls[idx][2] if len(calls[idx]) > 2 else 0
        value = random.choice([0, 10 ** 18, 2 * 10 ** 18]) if is_payable else orig_value
        caller = calls[idx][3] if len(calls[idx]) > 3 else random.choice(_BASE_CALLERS)
        calls[idx] = [fn, args, value, caller]
        return calls

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _random_arg(self, sol_type: str) -> str | int | bool:
        """Generate a plausible random value for a Solidity type."""
        if sol_type == "address":
            return "attacker_address"
        if sol_type == "bool":
            return random.choice([True, False])
        if "int" in sol_type:
            # Tier-1: width-correct boundary for uint*/int* (bytesN empty "0x" is
            # padded by Tier-2 _normalize_arg).
            return coerce_scalar(sol_type, random.choice(_UINT_BOUNDARIES))
        if "bytes" in sol_type:
            return "0x"
        return "0x0"


