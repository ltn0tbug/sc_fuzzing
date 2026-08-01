"""RandomFuzz entry point — wires the policy into the shared baseline loop."""

from __future__ import annotations

from rich.console import Console

from ..common.config import BaselineConfig
from ..common.loop import run_baseline_loop
from ..common.state import BaselineStateEncoder
from ...fuzzer.state import ContractFeatures
from .policy import RandomFuzzPolicy


def run_randomfuzz(
    config: BaselineConfig,
    contract_source: str,
    contract_abi: list[dict],
    *,
    verbose: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> tuple[list[dict], dict]:
    """Construct a RandomFuzz policy and run it through the baseline loop."""
    features = ContractFeatures.from_source(contract_source, contract_abi)
    enc_probe = BaselineStateEncoder(
        features, num_groups=RandomFuzzPolicy.num_groups, max_iterations=config.max_iterations,
    )
    policy = RandomFuzzPolicy(
        contract_abi=contract_abi,
        state_dim=enc_probe.state_dim,
        initial_balance_native=config.initial_balance_native,
        max_calls_per_item=config.max_calls_per_item,
        mode="fork" if getattr(config, "fork", None) else "inline",
    )
    return run_baseline_loop(
        config, contract_source, contract_abi, policy,
        verbose=verbose, debug=debug, console=console,
    )
