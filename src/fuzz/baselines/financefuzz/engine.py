"""FinanceFuzz evolutionary engine — port of ConFuzzius `engine/`.

Faithful to the paper's GA (Algorithm 1 + §6.1 hyperparameters): a population of
transaction-sequence individuals evolved by **linear-ranking selection**, **single-point
crossover** (concatenation with a length cap, pc=0.9), and **per-gene mutation**
(pm=0.1), with `MAX_INDIVIDUAL_LENGTH=20` and population reset after a number of stale
generations. Fitness = branch coverage measured on the forge run (supplied by the
runner).

Adaptation (documented in .README_AGENT.md): ConFuzzius's data-dependency
(taint-guided) selection/crossover variants need its symbolic taint analyzer, which has
no forge equivalent, so we use the plain linear-ranking + concatenation variants
(ConFuzzius ships both).
"""

from __future__ import annotations

import random
from bisect import bisect_right
from dataclasses import dataclass
from itertools import accumulate

from .generator import Generator, Tx


@dataclass
class Individual:
    """A transaction-sequence individual (chromosome = list of `Tx` genes)."""
    txs: list[Tx]
    fitness: float = 0.0          # branch coverage, assigned by the runner after eval
    evaluated: bool = False

    def clone(self) -> "Individual":
        return Individual(txs=[t.clone() for t in self.txs])

    @property
    def hash(self) -> str:
        return str([t.to_call() for t in self.txs])

    def to_calls(self) -> list:
        return [t.to_call() for t in self.txs]


class Population:
    def __init__(self, generator: Generator, size: int = 50, seed_length: int = 2) -> None:
        if size % 2 != 0:
            size += 1  # GA pairing needs an even size
        self.generator = generator
        self.size = size
        self.seed_length = seed_length
        self.individuals: list[Individual] = []

    def init(self) -> "Population":
        self.individuals = [
            Individual(txs=self.generator.generate_random_individual(self.seed_length))
            for _ in range(self.size)
        ]
        return self

    def best(self) -> Individual:
        return max(self.individuals, key=lambda i: i.fitness)


def linear_ranking_select(
    individuals: list[Individual], *, pmin: float = 0.1, pmax: float = 0.9,
) -> tuple[Individual, Individual]:
    """Pick a parent pair by linear-ranking selection (Baker 1985).

    Port of upstream `LinearRankingSelection`: sort ascending by fitness, assign
    linearly increasing selection probabilities, sample father on the cumulative
    wheel, mother = next rank (wraps)."""
    n = len(individuals)
    if n == 1:
        return individuals[0], individuals[0]
    ranked = sorted(individuals, key=lambda i: i.fitness)
    probs = [pmin] + [pmin + (pmax - pmin) * (i - 1) / (n - 1) for i in range(2, n)] + [pmax]
    psum = sum(probs)
    wheel = list(accumulate(p / psum for p in probs))
    f_idx = bisect_right(wheel, random.random())
    f_idx = min(f_idx, n - 1)
    m_idx = (f_idx + 1) % n
    return ranked[f_idx], ranked[m_idx]


def crossover(
    father: Individual, mother: Individual, *, pc: float = 0.9, max_len: int = 20,
) -> tuple[Individual, Individual]:
    """Concatenation crossover with a length cap (port of upstream `Crossover.cross`)."""
    f, m = father.clone(), mother.clone()
    if random.random() > pc or len(f.txs) + len(m.txs) > max_len:
        return f, m
    return Individual(txs=f.txs + m.txs), Individual(txs=m.txs + f.txs)


def mutate(indv: Individual, generator: Generator, *, pm: float = 0.1) -> Individual:
    """Per-gene mutation: independently re-sample caller / value / each argument
    with probability `pm` (port of upstream `Mutation.mutate`, minus the py-evm-only
    environment fields)."""
    for gene in indv.txs:
        if random.random() <= pm:
            gene.caller = generator.get_random_account()
        if random.random() <= pm:
            gene.value = generator.amount_for(gene.fn)
        arg_types = generator.interface.get(gene.fn, [])
        for i, t in enumerate(arg_types):
            if i < len(gene.args) and random.random() <= pm:
                gene.args[i] = generator.get_random_argument(t, gene.fn, i)
    indv.evaluated = False
    return indv


def next_generation(
    population: Population, *, pc: float = 0.9, pm: float = 0.1, max_len: int = 20,
    elitism: int = 1,
) -> list[Individual]:
    """Build the next generation from an evaluated population.

    Mirrors upstream `EvolutionaryFuzzingEngine.run`'s inner loop (size//2 select →
    cross → mutate pairs), plus light **elitism** (carry the top `elitism` individuals
    unchanged) so the best coverer is never lost — a standard GA safeguard."""
    gen = population.generator
    children: list[Individual] = []

    if elitism > 0:
        elites = sorted(population.individuals, key=lambda i: i.fitness, reverse=True)[:elitism]
        children.extend(e.clone() for e in elites)

    while len(children) < population.size:
        father, mother = linear_ranking_select(population.individuals)
        c1, c2 = crossover(father, mother, pc=pc, max_len=max_len)
        children.append(mutate(c1, gen, pm=pm))
        if len(children) < population.size:
            children.append(mutate(c2, gen, pm=pm))

    return children[:population.size]
