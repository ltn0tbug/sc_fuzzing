"""MADFuzz entry point — wires the policy into the shared baseline loop."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from ..common.config import BaselineConfig, resolve_external_addrs
from ..common.loop import run_baseline_loop
from ..common.state import BaselineStateEncoder
from ...fuzzer.state import ContractFeatures
from .policy import MADFuzzPolicy


def _load_ast_from_artifact(foundry_project: str, target: str) -> dict | None:
    """Pick up the AST from the per-contract artifact emitted by
    `forge build --ast`. Returns None if the artifact / AST isn't available
    (e.g. the user ran plain `forge build` outside the experiment runner).
    """
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


def run_madfuzz(
    config: BaselineConfig,
    contract_source: str,
    contract_abi: list[dict],
    *,
    verbose: bool = False,
    debug: bool = False,
    use_llm_seed: bool = True,
    llm_pool_prob: float = 0.3,
    console: Console | None = None,
) -> tuple[list[dict], dict]:
    # Load AST eagerly (artifact already on disk via `forge build --ast`).
    # Used by the seed-pool generator's source-budget pipeline (stage 2:
    # extract target contract + bases from multi-contract files).
    ast = _load_ast_from_artifact(config.foundry_project, config.contract_name)
    if ast is not None:
        features = ContractFeatures.from_ast(ast, contract_abi)
    else:
        features = ContractFeatures.from_source(contract_source, contract_abi)
    enc_probe = BaselineStateEncoder(
        features, num_groups=MADFuzzPolicy.num_groups, max_iterations=config.max_iterations,
    )
    policy = MADFuzzPolicy(
        contract_abi=contract_abi,
        contract_source=contract_source,
        state_dim=enc_probe.state_dim,
        rl_config=config.rl,
        llm_config=config.llm,
        initial_balance_native=config.initial_balance_native,
        max_calls_per_item=config.max_calls_per_item,
        llm_pool_prob=llm_pool_prob,
        use_llm_seed=use_llm_seed,
        ast=ast,
        target_name=config.contract_name,
        mode="fork" if getattr(config, "fork", None) else "inline",
        external_addrs=resolve_external_addrs(config),
    )
    return run_baseline_loop(
        config, contract_source, contract_abi, policy,
        verbose=verbose, debug=debug, console=console,
    )
