"""Experience replay buffer for DQN."""

import random
from collections import deque
from dataclasses import dataclass

import numpy as np


@dataclass
class Transition:
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool


class ReplayBuffer:
    def __init__(self, capacity: int = 1000):
        self._buffer: deque[Transition] = deque(maxlen=capacity)

    def push(self, transition: Transition) -> None:
        self._buffer.append(transition)

    def sample(self, batch_size: int) -> list[Transition]:
        return random.sample(self._buffer, batch_size)

    def __len__(self) -> int:
        return len(self._buffer)


class PrioritizedReplayBuffer:
    """Proportional Prioritized Experience Replay (Schaul et al. 2016).

    Transitions are sampled with probability ∝ priorityᵃ, where priority is the
    last-seen |TD error| (new transitions enter at max priority so each trains
    at least once). `sample` also returns importance-sampling weights that the
    caller multiplies into the loss to correct the non-uniform sampling bias.

    Backed by a numpy priority array + a list ring buffer rather than a sum-tree:
    with the project's 200-slot buffer a linear `np.random.choice` is simpler and
    fast enough; swap in a sum-tree only if the buffer grows orders of magnitude.

    Drop-in for ReplayBuffer except `sample` returns `(transitions, indices,
    is_weights)` and you must call `update_priorities(indices, td_errors)` after
    the gradient step.
    """

    def __init__(self, capacity: int = 1000, alpha: float = 0.6, eps: float = 1e-5):
        self.capacity = capacity
        self.alpha = alpha
        self.eps = eps
        self._storage: list[Transition] = []
        self._priorities = np.zeros(capacity, dtype=np.float64)
        self._pos = 0
        self._max_priority = 1.0

    def push(self, transition: Transition) -> None:
        if len(self._storage) < self.capacity:
            self._storage.append(transition)
        else:
            self._storage[self._pos] = transition
        # New transitions enter at max priority — guarantees ≥1 replay before
        # they can be deprioritized, so a rare reward can't be evicted unseen.
        self._priorities[self._pos] = self._max_priority
        self._pos = (self._pos + 1) % self.capacity

    def sample(self, batch_size: int, beta: float = 0.4):
        n = len(self._storage)
        prios = self._priorities[:n]
        probs = prios ** self.alpha
        probs /= probs.sum()
        indices = np.random.choice(n, batch_size, replace=False, p=probs)
        transitions = [self._storage[i] for i in indices]
        # IS weights: w_i = (N · P(i))^(-beta), normalized by max so they only
        # scale the loss down (≤1) — keeps the effective learning rate stable.
        weights = (n * probs[indices]) ** (-beta)
        weights /= weights.max()
        return transitions, indices, weights.astype(np.float32)

    def update_priorities(self, indices, td_errors) -> None:
        prios = np.abs(np.asarray(td_errors, dtype=np.float64)) + self.eps
        for i, p in zip(indices, prios):
            self._priorities[i] = p
            if p > self._max_priority:
                self._max_priority = p

    def __len__(self) -> int:
        return len(self._storage)
