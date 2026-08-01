"""LLM seed-pool generation for MADFuzz.

At startup, the policy calls the LLM once with the contract source and the
MADFuzz prompt. The original paper asks for per-function argument variants; we
adapt the prompt to instead return full **FuzzInput sequences** in our format,
so seeds can encode multi-step exploits (e.g., a configured reentrancy attack).

Returned schema (our `FuzzInput` format):

  [
    {
      "calls": [
        ["functionName", [arg1, arg2], "0x<wei_hex>", "caller_name"],
        ...
        // Optional first entry to arm the unified Attacker:
        // ["atk.setReentrantCall",
        //   {"reentrant_func": "fnName", "reentrant_args": [...], "max_count": N},
        //   "0x0", "attacker_address"]
      ],
      "description": "brief description"
    },
    ...
  ]

We parse this into `list[dict]` (FuzzInput-shaped) and the policy samples whole
sequences from the pool during hybrid exploration.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from ...config import LLMConfig
from ...llm.agent import _LLMClient, apply_source_budget
from ...llm.prompts import SEED_POOL_EXAMPLE, SEED_POOL_PROMPT
from ...llm.prompts.common import ARG_ENCODING_BLOCK

logger = logging.getLogger(__name__)


_VALID_CALLERS = ("attacker_address",)


def _extract_json_array(text: str) -> str:
    """Strip markdown fences and isolate the outermost JSON array, if present."""
    s = re.sub(r"```(?:json)?\s*", "", text).strip()
    start = s.find("[")
    end = s.rfind("]")
    if start != -1 and end != -1 and end > start:
        return s[start : end + 1]
    return s


def _normalize_value_wei(raw: Any) -> int:
    """Coerce an LLM-returned wei value (hex string, decimal string, int) to int."""
    if isinstance(raw, bool):
        return 0
    if isinstance(raw, int):
        return max(0, raw)
    s = str(raw or "0").strip()
    try:
        return max(0, int(s, 0))
    except (ValueError, TypeError):
        return 0


def _sanitize_caller(raw: Any) -> str:
    """Map an LLM-returned caller to an allowed alias; default to attacker_address."""
    s = str(raw or "").strip()
    if s in _VALID_CALLERS:
        return s
    # Common LLM mistakes (raw hex, deployer_address) → fall back to attacker
    return "attacker_address"


def _sanitize_setup_dict(raw: Any) -> dict | None:
    """Validate / normalize a setReentrantCall payload dict, return None if invalid.

    Drops the entry only when `reentrant_func` is missing/empty/non-string — the
    seed pool should not ship payloads the LLM gave up on.  An unknown function
    name (one not in the target ABI) is still accepted here; FoundryFuzzer's
    `_reentry_setup_lines` substitutes a random ABI function at execution time.
    """
    if not isinstance(raw, dict):
        return None
    func = str(raw.get("reentrant_func", "")).strip()
    if not func:
        return None
    args = raw.get("reentrant_args", [])
    if not isinstance(args, list):
        args = []
    try:
        max_count = int(raw.get("max_count", 3))
    except (ValueError, TypeError):
        max_count = 3
    max_count = max(1, min(5, max_count))
    return {
        "reentrant_func": func,
        "reentrant_args": list(args),
        "max_count": max_count,
    }


def _sanitize_call(raw: Any) -> list | None:
    """Validate / normalize a single call entry; return None if it's unusable."""
    if not isinstance(raw, list) or len(raw) < 1:
        return None
    fn = raw[0]
    if not isinstance(fn, str) or not fn:
        return None

    # Special: setReentrantCall — second element is a dict, value is wei hex, caller is alias
    if fn == "atk.setReentrantCall":
        setup = _sanitize_setup_dict(raw[1] if len(raw) > 1 else None)
        if setup is None:
            return None
        return [fn, setup, "0x0", "attacker_address"]

    # Regular call: [fn, [args], value_wei_hex_or_int, caller_name]
    args = raw[1] if len(raw) > 1 and isinstance(raw[1], list) else []
    value_wei = _normalize_value_wei(raw[2]) if len(raw) > 2 else 0
    caller = _sanitize_caller(raw[3]) if len(raw) > 3 else "attacker_address"
    return [fn, list(args), value_wei, caller]


def _sanitize_seed(raw: Any) -> dict | None:
    """Validate / normalize one FuzzInput-shaped seed dict, return None if invalid."""
    if not isinstance(raw, dict):
        return None
    raw_calls = raw.get("calls", [])
    if not isinstance(raw_calls, list) or not raw_calls:
        return None
    calls: list = []
    for rc in raw_calls:
        sc = _sanitize_call(rc)
        if sc is not None:
            calls.append(sc)
    if not calls:
        return None
    return {
        "calls": calls,
        "description": str(raw.get("description", "")),
    }


def generate_seed_pool(
    llm_config: LLMConfig,
    contract_source: str,
    contract_abi: list[dict],
    *,
    initial_balance_native: int = 10,
    ast: dict | None = None,
    target_name: str | None = None,
) -> tuple[list[dict], _LLMClient]:
    """Ask the LLM for FuzzInput-shaped attack sequences; return a list of seeds.

    Args:
      ast, target_name — optional, enables stage-2 of the source-budget
        pipeline (extract target contract + in-file bases) for multi-contract
        source files. When both are None, falls back to minify + truncate.

    Returns:
      pool — list of sanitized FuzzInput dicts (empty list on LLM failure)
      llm  — the underlying _LLMClient (so the caller can track token stats)
    """
    llm = _LLMClient(llm_config, initial_balance_native=initial_balance_native)
    llm.setup_abi(contract_abi)
    llm.set_source_context(ast, target_name)

    prompt = SEED_POOL_PROMPT.format(
        example_json=SEED_POOL_EXAMPLE,
        source_code=apply_source_budget(
            contract_source,
            llm_config.max_source_chars,
            ast=ast,
            target_name=target_name,
        ),
        max_items=llm_config.max_items_per_request,
        max_calls_per_item=llm_config.max_calls_per_item,
        arg_encoding=ARG_ENCODING_BLOCK,
    )

    pool: list[dict] = []
    max_retries = llm_config.llm_retries
    for attempt in range(1, max_retries + 1):
        try:
            raw = llm.complete(prompt)
            extracted = _extract_json_array(raw)
            items = json.loads(extracted)
            if not isinstance(items, list):
                items = [items]
            # Repackage bare-list responses (e.g. [[fn, args, val, caller], ...])
            # into FuzzInput dicts — shared with generator/mutator parse paths.
            from ...llm.agent import _LLMClient as _LC
            items = _LC.normalize_items(items)
            for entry in items:
                seed = _sanitize_seed(entry)
                if seed is not None:
                    pool.append(seed)
            break  # success
        except Exception as e:
            # Log the raw model output that failed to parse (consistent with
            # generator.py / mutator.py) so grammar-disable / truncation is
            # diagnosable without --debug.
            raw_preview = (getattr(llm, "last_response", "") or "")[:200]
            if attempt < max_retries:
                logger.warning(
                    "MADFuzz seed-pool generation attempt %d/%d failed (%s: %s) — retrying. raw: %r",
                    attempt, max_retries, type(e).__name__, e, raw_preview,
                )
            else:
                logger.warning(
                    "⚠ MADFuzz seed-pool generation failed after %d attempts (%s) — empty pool. "
                    "Hybrid exploration will run with random args only; check llama-cpp server logs. raw: %r",
                    max_retries, e, raw_preview,
                )

    if not pool:
        # Parse may have succeeded but every entry was dropped by _sanitize_seed
        # (e.g. all bare-list shapes the normalizer couldn't repackage). Empty
        # pool silently disables the LLM-seed branch of MADFuzz — surface it.
        logger.warning(
            "⚠ MADFuzz seed pool is empty after generation — LLM produced no usable "
            "FuzzInput dicts. Hybrid exploration degrades to pure DQN+random args."
        )
    return pool, llm
