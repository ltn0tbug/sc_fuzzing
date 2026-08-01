"""MADFuzz baseline (Quan et al., 2024).

Method:
  - LLM generates a seed pool of (function, args) candidates once at startup,
    using the prompt template in ref/madfuzz/llm/prompt/madfuzz.txt.
  - DQN selects one of 6 function groups (RLFuzz's 5 + a "status" group for view/pure).
  - 5 per-type DQNs (uint, int, bool, addr, byte) each select an index into the
    matching argument pool. Together they form the parameter generator.
  - During exploration, with some probability the policy samples a (function, args)
    set directly from the LLM seed pool instead of letting the per-type DQNs decide.

Like RLFuzz, the executor and reward function come from our shared infrastructure.
"""

from .policy import MADFuzzPolicy
from .runner import run_madfuzz
from .seed_gen import generate_seed_pool

__all__ = ["MADFuzzPolicy", "run_madfuzz", "generate_seed_pool"]
