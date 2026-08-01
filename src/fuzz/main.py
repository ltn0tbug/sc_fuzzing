"""Main fuzzing loop and CLI entry point."""

import json
import logging
import os
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler

from .config import FuzzerConfig, LLMConfig, RLConfig
from .llm.strategies import GENERATION_STRATEGIES
from .orchestrator import build_bugs_payload, run_fuzzing_loop
from .profiles import financefuzz_defaults, llmfuzz_defaults, madfuzz_defaults, sscfuzz_defaults
from .report import (
    backend_labels,
    default_output_path,
    resolve_run_log_path,
)

console = Console()
logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s",
    handlers=[RichHandler(console=console, show_path=False, show_time=False)],
)
# Suppress noisy SDK internal messages (e.g. rate_limit_event skips)
logging.getLogger("claude_agent_sdk").setLevel(logging.ERROR)


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """SC Fuzzer — Smart contract fuzzer using RL + LLM + Foundry."""


def _checkpoint_options(f):
    """Shared --checkpoint-* flags for standalone commands (off unless a path is
    given). With a path the run is resumable; --keep-checkpoint additionally
    preserves a final checkpoint at completion so a later higher --iterations run
    continues where it stopped (e.g. run 100, then run 200 to add 100 more)."""
    f = click.option("--keep-checkpoint", "keep_checkpoint", is_flag=True,
                     help="On clean completion keep a final checkpoint at the last iteration "
                          "(needs --checkpoint-path); re-run with a higher --iterations to continue.")(f)
    f = click.option("--checkpoint-every", "checkpoint_every", default=25, show_default=True, type=int,
                     help="Checkpoint flush cadence in iterations (with --checkpoint-path).")(f)
    f = click.option("--checkpoint-path", "checkpoint_path", default=None,
                     help="Enable iteration-level checkpointing/resume to this path (off by default).")(f)
    return f


def _apply_checkpoint(cfg, checkpoint_path, checkpoint_every, keep_checkpoint):
    """Wire the shared checkpoint flags onto a built config (no-op without a path)."""
    if checkpoint_path:
        cfg.checkpoint_path = checkpoint_path
        cfg.checkpoint_every = max(1, checkpoint_every)
        cfg.keep_checkpoint = keep_checkpoint
    return cfg


@cli.command("sscfuzz")
@click.argument("foundry_project", type=click.Path(exists=True))
@click.argument("contract_name")
@click.option("--abi", "abi_path", type=click.Path(exists=True), required=True,
              help="Path to contract ABI JSON file.")
@click.option("--source", "source_path", type=click.Path(exists=True), required=True,
              help="Path to contract Solidity source file.")
@click.option("--iterations", default=200, show_default=True,
              help="Maximum fuzzing iterations.")
@click.option("--output", default=None,
              help="Output path for found bugs JSON. Default: output/sscfuzz_<timestamp>.json")
@click.option("--model", default=sscfuzz_defaults.llm.model, show_default=True,
              help="Model name passed to the LLM backend.")
@click.option("--max-tokens", default=sscfuzz_defaults.llm.max_tokens, show_default=True,
              help="Max output tokens per LLM call. Increase if llama-cpp hits n_predict limit.")
@click.option("--temperature", default=sscfuzz_defaults.llm.temperature, show_default=True, type=float,
              help="LLM sampling temperature.")
@click.option(
    "--backend",
    type=click.Choice(["anthropic", "claude-code", "llama-cpp"], case_sensitive=False),
    default="anthropic",
    show_default=True,
    help=(
        "LLM backend to use.\n\n"
        "  anthropic   — Direct Anthropic API (requires ANTHROPIC_API_KEY).\n"
        "  claude-code — Local Claude Code CLI via Agent SDK.\n"
        "  llama-cpp   — Native llama.cpp /completion endpoint with GBNF grammar "
        "to guarantee valid JSON output. Model is loaded at server startup."
    ),
)
@click.option(
    "--backend-url",
    default=None,
    envvar="LLAMA_CPP_URL",
    show_default=True,
    help=(
        "Native llama.cpp endpoint URL (llama-cpp backend only). "
        "Can also be set via LLAMA_CPP_URL env var. "
        "Default: http://localhost:8080/completion"
    ),
)
@click.option(
    "--approach",
    type=click.Choice(["whitebox", "greybox"], case_sensitive=False),
    default=sscfuzz_defaults.llm.approach,
    show_default=True,
    help=(
        "LLM prompt context.\n\n"
        "  whitebox — full contract source code (LLM sees implementation).\n"
        "  greybox  — ABI only (LLM sees interface, not internals)."
    ),
)
@click.option("--max-source-chars", default=sscfuzz_defaults.llm.max_source_chars, show_default=True, type=int,
              help="Cap on contract source bytes in the prompt (whitebox only). 0 disables the cap.")
@click.option("--max-calls", default=sscfuzz_defaults.llm.max_calls_per_item, show_default=True,
              help="Maximum calls per fuzz sequence (enforced on LLM output and call_insert).")
@click.option("--run-log-path", "run_log_path", default=None,
              help="Explicit path for the full run log JSON. "
                   "Default: output/sscfuzz_run_log_<timestamp>.json.")
@click.option("--bug-report-only", is_flag=True,
              help="Write only the bug report; skip the full run log.")
@click.option("--debug", is_flag=True, help="Enable debug output (LLM inputs, forge results, RL state).")
@click.option(
    "--strategy",
    type=click.Choice(list(GENERATION_STRATEGIES), case_sensitive=False),
    default=None,
    help="Pin a single strategy, skipping RL selection.",
)
@_checkpoint_options
def fuzz(
    foundry_project: str,
    contract_name: str,
    abi_path: str,
    source_path: str,
    iterations: int,
    output: str | None,
    model: str,
    max_tokens: int,
    temperature: float,
    backend: str,
    backend_url: str | None,
    approach: str,
    max_source_chars: int,
    max_calls: int,
    run_log_path: str | None,
    bug_report_only: bool,
    debug: bool,
    strategy: str | None,
    checkpoint_path: str | None,
    checkpoint_every: int,
    keep_checkpoint: bool,
) -> None:
    """Run the fuzzer on a Foundry project."""
    raw = json.loads(Path(abi_path).read_text())
    # Foundry outputs {"abi": [...], "bytecode": ...}; accept both that and bare arrays.
    abi = raw["abi"] if isinstance(raw, dict) else raw
    source = Path(source_path).read_text()

    output = output or default_output_path("sscfuzz")
    run_log_path = resolve_run_log_path(run_log_path, "sscfuzz", bug_report_only=bug_report_only)

    llm_config = LLMConfig(model=model, backend=backend, approach=approach,
                           max_tokens=max_tokens, temperature=temperature,
                           max_source_chars=max_source_chars, max_calls_per_item=max_calls)
    if backend_url:
        llm_config.backend_url = backend_url

    config = FuzzerConfig(
        max_iterations=iterations,
        contract_name=contract_name,
        foundry_project=foundry_project,
        output_dir=str(Path(output).parent),
        rl=RLConfig(),
        llm=llm_config,
        # Apply the SScFuzz profile gate (5 dead mutations + boundary_values) so
        # the CLI `fuzz` command matches the experiment runner's active roster.
        disabled_strategies=sscfuzz_defaults.disabled_strategies,
    )
    _apply_checkpoint(config, checkpoint_path, checkpoint_every, keep_checkpoint)

    if backend == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        console.print("[red]ANTHROPIC_API_KEY environment variable not set.[/red]")
        console.print("Set it or use [yellow]--backend claude-code[/yellow] to use the local CLI instead.")
        raise SystemExit(1)

    # backend_labels auto-detects the served llama-cpp model name (the config's
    # `model` is only a placeholder for that backend).
    backend_label, model_label, _ = backend_labels(llm_config)

    bugs, run_log = run_fuzzing_loop(
        config, source, abi, debug=debug, pinned_strategy=strategy,
        backend_label=backend_label, model_label=model_label,
    )

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(
        build_bugs_payload(bugs, run_log, method="sscfuzz", contract=contract_name),
        indent=2,
    ))
    console.print(f"Bugs report written to [cyan]{out_path}[/cyan]")

    if run_log_path:
        rl_path = Path(run_log_path)
        rl_path.parent.mkdir(parents=True, exist_ok=True)
        rl_path.write_text(json.dumps(run_log, indent=2))
        console.print(f"Run log written to [cyan]{rl_path}[/cyan]")


@cli.command()
@click.argument("foundry_project", type=click.Path())
@click.argument("contract_name")
def init_project(foundry_project: str, contract_name: str) -> None:
    """Scaffold a new Foundry project for fuzzing."""
    project_path = Path(foundry_project)
    result = __import__("subprocess").run(
        ["forge", "init", str(project_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        console.print(f"[red]forge init failed:[/red] {result.stderr}")
        raise SystemExit(1)
    console.print(f"[green]Foundry project created at {project_path}[/green]")
    console.print(f"Place your contract at: [cyan]{project_path}/src/{contract_name}.sol[/cyan]")
    console.print("Then run: [yellow]sc-fuzz sscfuzz <project> <ContractName> --abi ... --source ...[/yellow]")


# ── Comparison baselines ──────────────────────────────────────────────────────

def _load_contract(abi_path: str, source_path: str) -> tuple[list[dict], str]:
    raw = json.loads(Path(abi_path).read_text())
    abi = raw["abi"] if isinstance(raw, dict) else raw
    source = Path(source_path).read_text()
    return abi, source


@cli.command("rlfuzz")
@click.argument("foundry_project", type=click.Path(exists=True))
@click.argument("contract_name")
@click.option("--abi", "abi_path", type=click.Path(exists=True), required=True)
@click.option("--source", "source_path", type=click.Path(exists=True), required=True)
@click.option("--iterations", default=200, show_default=True)
@click.option("--output", default=None,
              help="Output path for found bugs JSON. Default: output/rlfuzz_<timestamp>.json")
@click.option("--run-log-path", "run_log_path", default=None,
              help="Explicit path for the full run log JSON. "
                   "Default: output/<method>_run_log_<timestamp>.json.")
@click.option("--bug-report-only", is_flag=True,
              help="Write only the bug report; skip the full run log.")
@click.option("--max-calls", default=10, show_default=True,
              help="Max calls per fuzz sequence (synced with LLMConfig.max_calls_per_item).")
@click.option("--debug", is_flag=True)
@_checkpoint_options
def fuzz_rlfuzz(
    foundry_project: str, contract_name: str, abi_path: str, source_path: str,
    iterations: int, output: str | None, run_log_path: str | None, max_calls: int,
    bug_report_only: bool, debug: bool,
    checkpoint_path: str | None, checkpoint_every: int, keep_checkpoint: bool,
) -> None:
    """Run the RLFuzz baseline (function-group DQN + random args)."""
    from .baselines.common.config import BaselineConfig
    from .baselines.common.loop import write_outputs
    from .baselines.rlfuzz import run_rlfuzz

    output = output or default_output_path("rlfuzz")
    run_log_path = resolve_run_log_path(run_log_path, "rlfuzz", bug_report_only=bug_report_only)
    abi, source = _load_contract(abi_path, source_path)
    config = BaselineConfig(
        max_iterations=iterations,
        contract_name=contract_name,
        foundry_project=foundry_project,
        output_dir=str(Path(output).parent),
        max_calls_per_item=max_calls,
    )
    _apply_checkpoint(config, checkpoint_path, checkpoint_every, keep_checkpoint)
    bugs, run_log = run_rlfuzz(config, source, abi, debug=debug, console=console)
    write_outputs(output_path=output, run_log_path=run_log_path,
                  bugs=bugs, full_log=run_log, method="rlfuzz",
                  contract=contract_name, console=console)


@cli.command("madfuzz")
@click.argument("foundry_project", type=click.Path(exists=True))
@click.argument("contract_name")
@click.option("--abi", "abi_path", type=click.Path(exists=True), required=True)
@click.option("--source", "source_path", type=click.Path(exists=True), required=True)
@click.option("--iterations", default=200, show_default=True)
@click.option("--output", default=None,
              help="Output path for found bugs JSON. Default: output/madfuzz_<timestamp>.json")
@click.option("--run-log-path", "run_log_path", default=None,
              help="Explicit path for the full run log JSON. "
                   "Default: output/<method>_run_log_<timestamp>.json.")
@click.option("--bug-report-only", is_flag=True,
              help="Write only the bug report; skip the full run log.")
@click.option("--max-calls", default=madfuzz_defaults.max_calls_per_item, show_default=True,
              help="Max calls per fuzz sequence (synced with LLMConfig.max_calls_per_item).")
@click.option(
    "--backend",
    type=click.Choice(["anthropic", "claude-code", "llama-cpp"], case_sensitive=False),
    default="anthropic", show_default=True,
)
@click.option("--backend-url", default=None, envvar="LLAMA_CPP_URL")
@click.option("--model", default=madfuzz_defaults.llm.model, show_default=True)
@click.option("--max-tokens", default=madfuzz_defaults.llm.max_tokens, show_default=True,
              help="Max output tokens per LLM call (seed pool).")
@click.option("--temperature", default=madfuzz_defaults.llm.temperature, show_default=True, type=float,
              help="LLM sampling temperature.")
@click.option(
    "--approach",
    type=click.Choice(["whitebox", "greybox"], case_sensitive=False),
    default=madfuzz_defaults.llm.approach, show_default=True,
    help="LLM prompt context: whitebox (full source) | greybox (ABI only).",
)
@click.option("--max-source-chars", default=madfuzz_defaults.llm.max_source_chars, show_default=True, type=int,
              help="Cap on contract source bytes in the prompt (whitebox only). 0 disables the cap.")
@click.option("--no-llm-seed", is_flag=True,
              help="Disable LLM seed pool (use only the per-type DQNs; useful for ablations).")
@click.option("--llm-pool-prob", default=0.3, show_default=True, type=float,
              help="Probability of sampling args from the LLM seed pool at each step.")
@click.option("--debug", is_flag=True)
@_checkpoint_options
def fuzz_madfuzz(
    foundry_project: str, contract_name: str, abi_path: str, source_path: str,
    iterations: int, output: str | None, run_log_path: str | None, max_calls: int,
    backend: str, backend_url: str | None, model: str,
    max_tokens: int, temperature: float, approach: str, max_source_chars: int,
    no_llm_seed: bool, llm_pool_prob: float,
    bug_report_only: bool, debug: bool,
    checkpoint_path: str | None, checkpoint_every: int, keep_checkpoint: bool,
) -> None:
    """Run the MADFuzz baseline (6-group DQN + per-type arg DQNs + LLM seed pool)."""
    from .baselines.common.config import BaselineConfig
    from .baselines.common.loop import write_outputs
    from .baselines.madfuzz import run_madfuzz

    output = output or default_output_path("madfuzz")
    run_log_path = resolve_run_log_path(run_log_path, "madfuzz", bug_report_only=bug_report_only)
    abi, source = _load_contract(abi_path, source_path)
    llm_config = LLMConfig(model=model, backend=backend, approach=approach,
                           max_tokens=max_tokens, temperature=temperature,
                           max_source_chars=max_source_chars)
    if backend_url:
        llm_config.backend_url = backend_url
    config = BaselineConfig(
        max_iterations=iterations,
        contract_name=contract_name,
        foundry_project=foundry_project,
        output_dir=str(Path(output).parent),
        max_calls_per_item=max_calls,
        llm=llm_config,
    )
    _apply_checkpoint(config, checkpoint_path, checkpoint_every, keep_checkpoint)

    use_llm_seed = not no_llm_seed
    if use_llm_seed and backend == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        console.print(
            "[yellow]ANTHROPIC_API_KEY not set — disabling LLM seed pool. "
            "Use --no-llm-seed to silence this warning.[/yellow]"
        )
        use_llm_seed = False

    bugs, run_log = run_madfuzz(
        config, source, abi,
        debug=debug,
        use_llm_seed=use_llm_seed, llm_pool_prob=llm_pool_prob,
        console=console,
    )
    write_outputs(output_path=output, run_log_path=run_log_path,
                  bugs=bugs, full_log=run_log, method="madfuzz",
                  contract=contract_name, console=console)


@cli.command("randomfuzz")
@click.argument("foundry_project", type=click.Path(exists=True))
@click.argument("contract_name")
@click.option("--abi", "abi_path", type=click.Path(exists=True), required=True)
@click.option("--source", "source_path", type=click.Path(exists=True), required=True)
@click.option("--iterations", default=200, show_default=True)
@click.option("--output", default=None,
              help="Output path for found bugs JSON. Default: output/randomfuzz_<timestamp>.json")
@click.option("--run-log-path", "run_log_path", default=None,
              help="Explicit path for the full run log JSON. "
                   "Default: output/<method>_run_log_<timestamp>.json.")
@click.option("--bug-report-only", is_flag=True,
              help="Write only the bug report; skip the full run log.")
@click.option("--max-calls", default=10, show_default=True,
              help="Max calls per fuzz sequence.")
@click.option("--debug", is_flag=True)
@_checkpoint_options
def fuzz_randomfuzz(
    foundry_project: str, contract_name: str, abi_path: str, source_path: str,
    iterations: int, output: str | None, run_log_path: str | None, max_calls: int,
    bug_report_only: bool, debug: bool,
    checkpoint_path: str | None, checkpoint_every: int, keep_checkpoint: bool,
) -> None:
    """Run the RandomFuzz baseline (pure uniform random ABI sampling, no RL, no LLM)."""
    from .baselines.common.config import BaselineConfig
    from .baselines.common.loop import write_outputs
    from .baselines.randomfuzz import run_randomfuzz

    output = output or default_output_path("randomfuzz")
    run_log_path = resolve_run_log_path(run_log_path, "randomfuzz", bug_report_only=bug_report_only)
    abi, source = _load_contract(abi_path, source_path)
    config = BaselineConfig(
        max_iterations=iterations,
        contract_name=contract_name,
        foundry_project=foundry_project,
        output_dir=str(Path(output).parent),
        max_calls_per_item=max_calls,
    )
    _apply_checkpoint(config, checkpoint_path, checkpoint_every, keep_checkpoint)
    bugs, run_log = run_randomfuzz(
        config, source, abi,
        debug=debug, console=console,
    )
    write_outputs(output_path=output, run_log_path=run_log_path,
                  bugs=bugs, full_log=run_log, method="randomfuzz",
                  contract=contract_name, console=console)


@cli.command("llmfuzz")
@click.argument("foundry_project", type=click.Path(exists=True))
@click.argument("contract_name")
@click.option("--abi", "abi_path", type=click.Path(exists=True), required=True)
@click.option("--source", "source_path", type=click.Path(exists=True), required=True)
@click.option("--iterations", default=200, show_default=True)
@click.option("--output", default=None,
              help="Output path for found bugs JSON. Default: output/llmfuzz_<timestamp>.json")
@click.option("--run-log-path", "run_log_path", default=None,
              help="Explicit path for the full run log JSON. "
                   "Default: output/<method>_run_log_<timestamp>.json.")
@click.option("--bug-report-only", is_flag=True,
              help="Write only the bug report; skip the full run log.")
@click.option("--max-calls", default=llmfuzz_defaults.max_calls_per_item, show_default=True,
              help="Max calls per fuzz sequence.")
@click.option(
    "--backend",
    type=click.Choice(["anthropic", "claude-code", "llama-cpp"], case_sensitive=False),
    default="anthropic", show_default=True,
)
@click.option("--backend-url", default=None, envvar="LLAMA_CPP_URL")
@click.option("--model", default=llmfuzz_defaults.llm.model, show_default=True)
@click.option("--max-tokens", default=llmfuzz_defaults.llm.max_tokens, show_default=True,
              help="Max output tokens per LLM call.")
@click.option("--temperature", default=llmfuzz_defaults.llm.temperature, show_default=True, type=float,
              help="LLM sampling temperature.")
@click.option(
    "--approach",
    type=click.Choice(["whitebox", "greybox"], case_sensitive=False),
    default=llmfuzz_defaults.llm.approach, show_default=True,
    help="LLM prompt context: whitebox (full source) | greybox (ABI only).",
)
@click.option("--max-source-chars", default=llmfuzz_defaults.llm.max_source_chars, show_default=True, type=int,
              help="Cap on contract source bytes in the prompt (whitebox only). 0 disables the cap.")
@click.option("--debug", is_flag=True)
@_checkpoint_options
def fuzz_llmfuzz(
    foundry_project: str, contract_name: str, abi_path: str, source_path: str,
    iterations: int, output: str | None, run_log_path: str | None, max_calls: int,
    backend: str, backend_url: str | None, model: str,
    max_tokens: int, temperature: float, approach: str, max_source_chars: int,
    bug_report_only: bool, debug: bool,
    checkpoint_path: str | None, checkpoint_every: int, keep_checkpoint: bool,
) -> None:
    """Run the LLMFuzz baseline (LLM-only, uniform over the gated gen+mut roster, no RL)."""
    from .baselines.common.config import BaselineConfig
    from .baselines.common.loop import write_outputs
    from .baselines.llmfuzz import run_llmfuzz

    if backend == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        console.print(
            "[red]ANTHROPIC_API_KEY not set. Set it or use --backend claude-code / --backend llama-cpp.[/red]"
        )
        raise SystemExit(1)

    output = output or default_output_path("llmfuzz")
    run_log_path = resolve_run_log_path(run_log_path, "llmfuzz", bug_report_only=bug_report_only)
    abi, source = _load_contract(abi_path, source_path)
    llm_config = LLMConfig(model=model, backend=backend, approach=approach,
                           max_tokens=max_tokens, temperature=temperature,
                           max_source_chars=max_source_chars, max_calls_per_item=max_calls)
    if backend_url:
        llm_config.backend_url = backend_url
    config = BaselineConfig(
        max_iterations=iterations,
        contract_name=contract_name,
        foundry_project=foundry_project,
        output_dir=str(Path(output).parent),
        max_calls_per_item=max_calls,
        llm=llm_config,
        # Apply the LLMFuzz profile gate so the CLI's active roster (gen+mut)
        # matches the experiment runner's.
        disabled_strategies=llmfuzz_defaults.disabled_strategies,
    )
    _apply_checkpoint(config, checkpoint_path, checkpoint_every, keep_checkpoint)
    bugs, run_log = run_llmfuzz(
        config, source, abi,
        debug=debug, console=console,
    )
    write_outputs(output_path=output, run_log_path=run_log_path,
                  bugs=bugs, full_log=run_log, method="llmfuzz",
                  contract=contract_name, console=console)


@cli.command("financefuzz")
@click.argument("foundry_project", type=click.Path(exists=True))
@click.argument("contract_name")
@click.option("--abi", "abi_path", type=click.Path(exists=True), required=True)
@click.option("--source", "source_path", type=click.Path(exists=True), required=True)
@click.option("--generations", default=8, show_default=True, help="GA generations.")
@click.option("--population", default=financefuzz_defaults.population, show_default=True,
              help="GA population size.")
@click.option("--max-calls", default=financefuzz_defaults.max_individual_length, show_default=True,
              help="Max transactions per individual (MAX_INDIVIDUAL_LENGTH).")
@click.option("--equivalence-elite", default=financefuzz_defaults.equivalence_elite, show_default=True,
              help="Run the T->T' equivalence variants only on the top-N individuals each generation.")
@click.option("--output", default=None,
              help="Output path for found bugs JSON. Default: output/financefuzz_<timestamp>.json")
@click.option("--run-log-path", "run_log_path", default=None,
              help="Explicit path for the full run log JSON. "
                   "Default: output/<method>_run_log_<timestamp>.json.")
@click.option("--bug-report-only", is_flag=True,
              help="Write only the bug report; skip the full run log.")
@click.option("--debug", is_flag=True)
def fuzz_financefuzz(
    foundry_project: str, contract_name: str, abi_path: str, source_path: str,
    generations: int, population: int, max_calls: int, equivalence_elite: int,
    output: str | None, run_log_path: str | None, bug_report_only: bool, debug: bool,
) -> None:
    """Run the FinanceFuzz competitor (evolutionary engine + financial-property oracle)."""
    from .baselines.common.config import BaselineConfig
    from .baselines.common.loop import write_outputs
    from .baselines.financefuzz import run_financefuzz

    output = output or default_output_path("financefuzz")
    run_log_path = resolve_run_log_path(run_log_path, "financefuzz", bug_report_only=bug_report_only)
    abi, source = _load_contract(abi_path, source_path)
    config = BaselineConfig(
        max_iterations=generations * population,
        contract_name=contract_name,
        foundry_project=foundry_project,
        output_dir=str(Path(output).parent),
        max_calls_per_item=max_calls,
    )
    bugs, run_log = run_financefuzz(
        config, source, abi,
        generations=generations, population=population,
        max_individual_length=max_calls, equivalence_elite=equivalence_elite,
        debug=debug, console=console,
    )
    write_outputs(output_path=output, run_log_path=run_log_path,
                  bugs=bugs, full_log=run_log, method="financefuzz",
                  contract=contract_name, console=console)


if __name__ == "__main__":
    cli()
