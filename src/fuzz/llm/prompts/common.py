"""Prompt fragments shared across templates.

Single source of truth for text that MUST stay identical between the sscfuzz
generation prompt and the MADFuzz seed-pool prompt, so the two backends can't
drift on how the model is told to encode arguments.
"""

# Per-ABI-type argument encoding contract. Injected (verbatim) into both
# GEN_PROMPT_TMPL and SEED_POOL_PROMPT via an {arg_encoding} placeholder.
ARG_ENCODING_BLOCK = """**Argument encoding (match each value to its ABI parameter type):**
- uint* / bytesN / bytes → hex string, e.g. "0x1f" (minimal, not zero-padded)
- int* (signed) → decimal string, e.g. "-5"
- bool → true or false (JSON literal, unquoted)
- address → an alias name (see callers/aliases above) or a 40-hex-digit 0x literal
- arrays → JSON list, e.g. [] or ["0x1", "0x2"]; tuples/structs → JSON list of their fields
- empty bytes / empty signature / empty proof → "0x" or []"""
