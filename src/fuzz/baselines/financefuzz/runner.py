"""FinanceFuzz competitor entry point.

Drives the ported evolutionary engine over the forge execution backend and applies
FinanceFuzz's financial-property oracle, emitting bug/run-log records in the project's
standard schema so the competitor lines up in the comparison tables.

Signature matches the experiment runner's `MethodSpec.entry` contract:
    run_financefuzz(config, source, abi, *, verbose, debug, console) -> (bugs, run_log)
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...report import (
    build_bug_record,
    build_run_record,
    build_run_summary,
    render_done_panel,
    render_start_panel,
    spec_for,
)
from ..common.config import BaselineConfig
from . import engine as E
from . import oracle as O
from .execution import FinanceExecutor
from .generator import Generator

logger = logging.getLogger(__name__)

METHOD = "financefuzz"


def run_financefuzz(
    config: BaselineConfig,
    contract_source: str,
    contract_abi: list[dict],
    *,
    generations: int | None = None,
    population: int = 12,
    p_crossover: float = 0.9,
    p_mutation: float = 0.1,
    max_individual_length: int = 20,
    stale_reset: int = 10,
    equivalence_elite: int = 4,
    verbose: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> tuple[list[dict], dict]:
    """Run the FinanceFuzz competitor and return (found_bugs, full_run_log).

    `generations` defaults to the regime budget (`config.max_iterations`, the total
    individual budget) divided by `population`, so the experiment runner's
    test/long/very_long modes set the GA budget the same way they set iteration
    counts for the other methods. The CLI passes `generations` explicitly."""
    console = console or Console()
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    population = max(2, population)
    if generations is None:
        generations = max(1, int(getattr(config, "max_iterations", 96)) // population)

    spec = spec_for(METHOD)
    total_budget = generations * population
    console.print(render_start_panel(
        spec, contract=config.contract_name, iterations=total_budget,
    ))

    executor = FinanceExecutor(
        config.foundry_project,
        config.contract_name,
        abi=contract_abi,
        initial_balance_native=config.initial_balance_native,
        contract_source=contract_source,
        fork=getattr(config, "fork", None),
        constructor_args=getattr(config, "constructor_args", None),
        constructor_value=getattr(config, "constructor_value", None),
        pre_deploy=getattr(config, "pre_deploy", None),
        setup_calls=getattr(config, "setup_calls", None),
        external=getattr(config, "external", None),
        setup_template=getattr(config, "setup_template", None),
    )
    if not executor.compile():
        console.print("[red]Compilation failed. Aborting.[/red]")
        return [], {"summary": {}, "iterations": [], "bugs": []}
    # Modern (>=0.8) / legacy (<0.8) inline and on-chain fork are all supported via
    # the matching finance_*.sol.tpl deploy path (see execution._build_test).

    generator = Generator(contract_abi, initial_balance_native=config.initial_balance_native)
    if not generator.function_names:
        console.print("[yellow]No callable functions in ABI — nothing to fuzz.[/yellow]")
        return [], {"summary": {"method": METHOD}, "iterations": [], "bugs": []}

    pop = E.Population(generator, size=population, seed_length=3).init()

    found_bugs: list[dict] = []
    run_records: list[dict] = []
    seen_bug_keys: set[str] = set()      # dedupe (detector, fn) so reruns don't double-count
    detector_counts: dict[str, int] = {}
    run_id = 0
    best_fitness = -1.0
    best_fitness_overall = -1.0
    best_calls: list = []
    stale = 0

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        transient=not debug, console=console,
    ) as progress:
        task = progress.add_task("financefuzz...", total=total_budget)
        for gen in range(generations):
            # Evaluate every individual: run T (+ equivalence variants on the elite
            # subset) and score fitness = branch coverage.
            elite_idx = _elite_indices(pop.individuals, equivalence_elite)
            # Best individual this generation — gets the one per-gen coverage dump (F2).
            gen_best_fit = float("-inf")
            gen_best_calls: list | None = None
            gen_best_fo: dict | None = None
            for i, indv in enumerate(pop.individuals):
                calls = indv.to_calls()
                variants = (
                    O.build_variants(calls) if i in elite_idx else []
                )
                result = executor.run_individual(calls, variants, debug=debug)

                # Invariant is always parsed from the T run; equivalence violations
                # only appear when variants were rendered (elite individuals).
                violations = O.interpret(result.decoded_logs)
                indv.fitness = _fitness(calls, result.decoded_logs, violations)
                indv.evaluated = True
                if indv.fitness > best_fitness_overall:
                    best_fitness_overall, best_calls = indv.fitness, calls
                for v in violations:
                    detector_counts[v.detector] = detector_counts.get(v.detector, 0) + 1
                    # One bug per vulnerability type per contract (FinanceFuzz reports
                    # per (contract, type)); count occurrences in detector_counts.
                    key = v.detector
                    fn0 = next((c[0] for c in calls if c and c[0] != 'atk.setReentrantCall'), None)
                    if key not in seen_bug_keys:
                        seen_bug_keys.add(key)
                        found_bugs.append(build_bug_record(
                            spec, iteration=run_id, bug_type=v.bug_type, fn_name=fn0,
                            fuzz_input={"calls": calls}, revert_reason=v.message,
                            trace=v.message,
                        ))
                        console.print(
                            f"\n[red bold]BUG[/red bold] gen={gen} {v.bug_type} ({v.detector})"
                        )

                fo = {
                    "coverage": round(result.coverage, 6),
                    "new_bc_branches": result.new_bc_branches,
                    "bc_branches_total": result.bc_branches_total,
                    # Filled below for the gen's best individual only; empty otherwise.
                    "coverage_bc_branch_ids": [],
                    "new_branches": result.new_branches,
                    "branches_total": result.branches_total,
                    "forge_status": result.forge_status,
                    # Per-iter bug flag (F4/F10) — free from the detectors' violations.
                    "bug_found": bool(violations),
                    "violations": [v.detector for v in violations],
                    "is_elite": i in elite_idx,
                }
                run_records.append(build_run_record(
                    spec, run_id=run_id, iteration=gen,
                    fn_name=calls[0][0] if calls else None,
                    fuzz_input={"calls": calls},
                    fuzzing_output=fo,
                ))
                if indv.fitness > gen_best_fit:
                    gen_best_fit, gen_best_calls, gen_best_fo = indv.fitness, calls, fo
                run_id += 1
                progress.update(task, description=f"[gen {gen + 1}/{generations}] financefuzz "
                                                  f"bugs={len(found_bugs)}")
                progress.advance(task)

            # One coverage dump per generation (best individual) → per-iter F2 branch ids,
            # without paying the dump on every GA eval.
            if gen_best_calls and gen_best_fo is not None:
                try:
                    cov_res = executor.run_coverage(gen_best_calls)
                    gen_best_fo["coverage_bc_branch_ids"] = [
                        list(b) for b in sorted(cov_res.bc_branches_this_run)
                    ]
                    gen_best_fo["bc_branches_total"] = cov_res.bc_branches_total
                except Exception as e:  # coverage is best-effort; never fail the run
                    logger.debug("FinanceFuzz per-gen coverage dump failed: %s", e)

            # Stale-reset (paper §6.1) + evolve the next generation.
            cur_best = max(i.fitness for i in pop.individuals)
            if cur_best > best_fitness + 1e-9:
                best_fitness, stale = cur_best, 0
            else:
                stale += 1
            if stale >= stale_reset:
                pop.init()
                stale = 0
            else:
                pop.individuals = E.next_generation(
                    pop, pc=p_crossover, pm=p_mutation, max_len=max_individual_length,
                )

    # Final pass on the overall-best individual — ensures it's in cumulative coverage
    # even if its generation's dump hit the size cap.
    if best_calls:
        try:
            executor.run_coverage(best_calls)
        except Exception as e:  # coverage is best-effort; never fail the run over it
            logger.debug("FinanceFuzz coverage pass failed: %s", e)
    cov = executor.measure_coverage()
    console.print(render_done_panel(
        spec, total_reward=0.0, cov=cov, bugs_found=len(found_bugs),
    ))

    full_log = {
        "summary": build_run_summary(
            spec, cov=cov, run_records=run_records, total_reward=0.0,
            total_iterations=total_budget, total_bugs=len(found_bugs),
            extra={"detector_counts": detector_counts,
                   "generations": generations, "population": population},
        ),
        "iterations": run_records,
        "bugs": found_bugs,
    }
    return found_bugs, full_log


def _fitness(calls: list, decoded_logs: list, violations: list) -> float:
    """Cheap log-derived fitness (no coverage dump): reward T-block calls that ran
    without reverting (reaching more contract behaviour), the sequence length (more
    state interaction), and any property violation found. Drives the GA toward
    deeper, bug-triggering sequences."""
    plain = [c for c in calls if c and c[0] != "atk.setReentrantCall"]
    t_fails = O.parse_block_failures(decoded_logs).get("T", set())
    successful = max(0, len(plain) - len(t_fails))
    return float(successful) + 0.01 * len(plain) + 5.0 * len(violations)


def _elite_indices(individuals: list, k: int) -> set[int]:
    """Indices of the top-k individuals by fitness (equivalence checks run only on
    these to bound forge calls; the first generation has no fitness yet → all)."""
    if k <= 0 or k >= len(individuals):
        return set(range(len(individuals)))
    if all(not getattr(i, "evaluated", False) for i in individuals):
        return set(range(len(individuals)))
    ranked = sorted(range(len(individuals)), key=lambda j: individuals[j].fitness, reverse=True)
    return set(ranked[:k])
