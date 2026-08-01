"""Centralized LLM prompts.

All user-facing prompt text (system prompts, gen/mut templates, MADFuzz seed
prompt, ChatML wrapper) lives here. Generation / mutation strategy *metadata* (goal,
technique, example_sequence, caller_hints) stays in `llm/strategies.py` —
this package only houses the prompt-shaped text those metadata get
formatted into.

Single-import entry points for downstream consumers:
  from fuzz.llm.prompts import (
      SYSTEM_PROMPT,        # the audit-persona instruction
      GEN_PROMPT_TMPL,      # Generator user prompt template
      MUT_PROMPT_TMPL,      # LLMMutator user prompt template
      SEED_POOL_PROMPT,     # MADFuzz seed-pool prompt
      SEED_POOL_EXAMPLE,    # in-prompt JSON example for seed pool
      CHATML_TEMPLATE,      # ChatML wrapper used by llama-cpp backend
  )
"""

from .system import SYSTEM_PROMPT
from .generation import GEN_PROMPT_TMPL
from .mutation import MUT_PROMPT_TMPL
from .seed_pool import SEED_POOL_PROMPT, SEED_POOL_EXAMPLE
from .chatml import CHATML_TEMPLATE
from .common import ARG_ENCODING_BLOCK

__all__ = [
    "SYSTEM_PROMPT",
    "GEN_PROMPT_TMPL",
    "MUT_PROMPT_TMPL",
    "SEED_POOL_PROMPT",
    "SEED_POOL_EXAMPLE",
    "CHATML_TEMPLATE",
    "ARG_ENCODING_BLOCK",
]
