"""LLMGenerator actor — creates fuzz inputs from scratch using the LLM."""

from __future__ import annotations

import json
import logging

from ..config import LLMConfig
from .agent import FuzzInput, TokenUsage, _LLMClient, _truncate_prompt
from .random_gen import random_fuzz_input
from .prompts import GEN_PROMPT_TMPL, SYSTEM_PROMPT
from .prompts.common import ARG_ENCODING_BLOCK
from .strategies import GENERATION_STRATEGY_PROMPTS

logger = logging.getLogger(__name__)


class LLMGenerator:
    """LLM-backed generator actor.

    Receives a strategy name and creates fuzz inputs from scratch by prompting
    the LLM with the strategy's goal and technique.  Maintains its. own run
    history to give the LLM context about what has been tried before.
    """

    def __init__(self, config: LLMConfig, initial_balance_native: int = 10):
        self._llm = _LLMClient(config, initial_balance_native)
        # Mode-aware address pool for the LLM-exhausted random fallback; set by the
        # orchestrator via set_address_pool(). None → random_gen synthesizes an
        # inline pool with no externals.
        self._address_pool: list[str] | None = None

    @property
    def token_stats(self) -> TokenUsage:
        return self._llm.token_stats

    def setup_abi(self, abi: list[dict]) -> None:
        self._llm.setup_abi(abi)

    def set_external(self, external: list[dict] | None) -> None:
        """Register declared external contracts (extend.external) on the shared LLM
        client — drives the prompt's external section + the llama-cpp grammar."""
        self._llm.set_external(external)

    def set_address_pool(self, address_pool: list[str] | None) -> None:
        """Register the mode-aware address pool used by the random fallback."""
        self._address_pool = address_pool

    def set_source_context(self, ast: dict | None, target_name: str | None) -> None:
        """Forward AST + target contract name to the underlying LLM client so
        `build_contract_context` can apply stage-2 (extract target) of the
        source-budget pipeline."""
        self._llm.set_source_context(ast, target_name)

    def format_history_rich(self, strategy: str | None = None) -> str:
        return self._llm.format_history_rich(strategy)

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
        fallback: bool = False,
    ) -> None:
        self._llm.record_run(fuzz_input, reward, forge_status, raw_reason, new_branches, decoded_logs, strategy, mode, fallback)

    def generate(
        self,
        contract_source: str,
        contract_abi: list[dict],
        strategy: str,
        n: int = 1,
        debug: bool = False,
    ) -> list[FuzzInput]:
        """Generate *n* fuzz inputs from scratch for the given strategy."""
        self._llm.setup_abi(contract_abi)
        prompt_def = GENERATION_STRATEGY_PROMPTS[strategy]
        context = self._llm.build_contract_context(contract_source, contract_abi)
        history = self._llm.format_history(strategy)
        caller_list = ", ".join(f'"{c}"' for c in prompt_def["caller_hints"])
        extend_section = (
            f"\n**Strategy notes:** {prompt_def['extend_hints']}"
            if prompt_def["extend_hints"]
            else ""
        )
        # Declared external contracts + $ret chaining rule ("" when target-only).
        extend_section += self._llm.external_prompt_section()

        max_seq = self._llm.config.max_calls_per_item
        user_prompt = GEN_PROMPT_TMPL.format(
            context=context,
            n=n,
            strategy=strategy,
            max_calls_per_item=max_seq,
            goal=prompt_def["goal"],
            technique=prompt_def["technique"],
            value_hints=prompt_def["value_hints"],
            caller_list=caller_list,
            extend_section=extend_section,
            arg_encoding=ARG_ENCODING_BLOCK,
            example=prompt_def["example_sequence"],
            history=history,
        )

        if debug:
            logger.debug("LLM system prompt:\n%s", SYSTEM_PROMPT)
            logger.debug("LLM mode: GENERATE")
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
                # Log the raw model output that failed to parse so the failure is
                # diagnosable without --debug. last_response holds the offending
                # text for parse/normalize errors (it's stale only for connection
                # errors raised inside complete() before a response arrives).
                raw_preview = (self._llm.last_response or "")[:200]
                if attempt < max_retries:
                    logger.warning(
                        "generate() attempt %d/%d failed (%s: %s) — retrying. raw: %r",
                        attempt, max_retries, type(e).__name__, e, raw_preview,
                    )
                else:
                    last_err = f"{type(e).__name__}: {e} | raw: {raw_preview!r}"
        logger.warning(
            "⚠ LLM generate() exhausted %d retries (strategy=%s) — falling back to "
            "uniform-ABI random input via llm.random_gen.random_fuzz_input "
            "(last error: %s). This iteration is random-equivalent, not LLM-guided; "
            "check llama-cpp server logs and grammar validity.",
            max_retries, strategy, last_err,
        )
        self._llm.last_fallback_reason = f"llm_exhausted: {last_err}"
        # Boundary-pool random input: uniform over ABI functions with per-type arg
        # pools and a 20% chance of a reentrancy-setup head. Strictly better than
        # the old zero-fill behaviour (which set every arg to 0 and ran one call,
        # producing a sequence that nearly always reverts on address-zero / amount
        # checks). The same helper backs the ε-greedy random-input branch in orchestrator.py,
        # so the fallback now matches the quality tier of intentional injection.
        max_seq = self._llm.config.max_calls_per_item
        return [
            FuzzInput.from_dict(random_fuzz_input(
                contract_abi,
                max_calls=max_seq,
                initial_balance_native=self._llm.initial_balance_native,
                address_pool=self._address_pool,
            ))
            for _ in range(n)
        ]

