"""RLFuzz entry point — wires the policy into the shared baseline loop."""

from __future__ import annotations

from rich.console import Console

from ..common.config import BaselineConfig, resolve_external_addrs
from ..common.loop import run_baseline_loop
from ..common.state import BaselineStateEncoder
from ...fuzzer.state import ContractFeatures
from .policy import RLFuzzPolicy


def run_rlfuzz(
    config: BaselineConfig,
    contract_source: str,
    contract_abi: list[dict],
    *,
    verbose: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> tuple[list[dict], dict]:
    """Construct an RLFuzz policy and run it through the baseline loop."""
    # Compute state dim by spinning up a throwaway encoder with the right num_groups.
    features = ContractFeatures.from_source(contract_source, contract_abi)
    enc_probe = BaselineStateEncoder(
        features, num_groups=RLFuzzPolicy.num_groups, max_iterations=config.max_iterations,
    )
    policy = RLFuzzPolicy(
        contract_abi=contract_abi,
        contract_source=contract_source,
        state_dim=enc_probe.state_dim,
        rl_config=config.rl,
        initial_balance_native=config.initial_balance_native,
        max_calls_per_item=config.max_calls_per_item,
        mode="fork" if getattr(config, "fork", None) else "inline",
        external_addrs=resolve_external_addrs(config),
    )
    return run_baseline_loop(
        config, contract_source, contract_abi, policy,
        verbose=verbose, debug=debug, console=console,
    )
