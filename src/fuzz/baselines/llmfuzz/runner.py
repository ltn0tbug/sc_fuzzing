"""LLMFuzz entry point — wires the policy into the shared baseline loop."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from ..common.config import BaselineConfig
from ..common.loop import run_baseline_loop
from ..common.state import BaselineStateEncoder
from ...fuzzer.state import ContractFeatures
from .policy import LLMFuzzPolicy


def _load_ast_from_artifact(foundry_project: str, target: str) -> dict | None:
    out_dir = Path(foundry_project) / "out"
    if not out_dir.is_dir():
        return None
    for path in out_dir.glob(f"*.sol/{target}.json"):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        ast = data.get("ast")
        if isinstance(ast, dict) and ast.get("nodeType") == "SourceUnit":
            return ast
    return None


def run_llmfuzz(
    config: BaselineConfig,
    contract_source: str,
    contract_abi: list[dict],
    *,
    verbose: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> tuple[list[dict], dict]:
    """Construct an LLMFuzz policy and run it through the baseline loop."""
    ast = _load_ast_from_artifact(config.foundry_project, config.contract_name)
    if ast is not None:
        features = ContractFeatures.from_ast(ast, contract_abi)
    else:
        features = ContractFeatures.from_source(contract_source, contract_abi)

    enc_probe = BaselineStateEncoder(
        features, num_groups=LLMFuzzPolicy.num_groups, max_iterations=config.max_iterations,
    )
    policy = LLMFuzzPolicy(
        contract_abi=contract_abi,
        contract_source=contract_source,
        llm_config=config.llm,
        state_dim=enc_probe.state_dim,
        initial_balance_native=config.initial_balance_native,
        ast=ast,
        target_name=config.contract_name,
        debug=debug,
        disabled_strategies=getattr(config, "disabled_strategies", ()),
        rl_config=config.rl,
    )
    return run_baseline_loop(
        config, contract_source, contract_abi, policy,
        verbose=verbose, debug=debug, console=console,
    )
