"""RLFuzz baseline (Su et al., 2022).

Method:
  - DQN selects one of 5 function groups (pay-call, nopay-call, pay-nocall,
    nopay-nocall-store, selfdestruct).
  - A random function is sampled uniformly from the chosen group.
  - Arguments are sampled uniformly at random per Solidity type from fixed pools.

This is the policy. The execution backend, reward function, and DQN network are
reused from our shared infrastructure for fair comparison.
"""

from .policy import RLFuzzPolicy
from .runner import run_rlfuzz

__all__ = ["RLFuzzPolicy", "run_rlfuzz"]
