"""Generation-mode user prompt template.

Consumed by `llm.generator.LLMGenerator.generate()`. Strategy metadata
(goal / technique / value_hints / caller_list / extend_hints / example) is
injected from `llm.strategies.GENERATION_STRATEGY_PROMPTS`.

Placeholders:
  {context}              ABI or whitebox source context (build_contract_context)
  {strategy}             current RL-selected strategy name
  {max_calls_per_item}   per-sequence call cap
  {goal}                 short bug-class objective
  {technique}            multi-sentence attack recipe
  {value_hints}          per-strategy ETH/uint hex hints
  {caller_list}          quoted comma-joined caller aliases
  {extend_section}       optional strategy-specific guidance (or "")
  {arg_encoding}         per-ABI-type argument encoding contract (prompts.common)
  {n}                    requested number of fuzz-input objects
  {example}              JSON example sequence (placeholder-shaped post-rename)
  {history}              recent run history (formatted by _LLMClient)
"""

GEN_PROMPT_TMPL = """\
{context}

## Fuzzing task — strategy: {strategy}

**Objective:** Build a transaction sequence in which the attacker-controlled address (attacker_address) ends up with more total value (native coin + tokens) than it spent — i.e. extract funds from the target or break a value invariant in the attacker's favor. Use at most {max_calls_per_item} calls per sequence.

**Goal:** {goal}

**Technique:**
{technique}

**Value hints:** {value_hints}

**Valid callers:** {caller_list}
Use only these alias name(s) in the `caller_name` (msg.sender) slot — there is a
single attacker identity, so every call already runs as the attacker. Never use
"deployer_address" or a raw hex address as a caller. (Address-TYPED ARGUMENTS are
separate: see "Special argument values" below for the aliases those slots accept —
you are NOT restricted to the caller alias there.){extend_section}

{arg_encoding}

**Output format:**
Return a JSON array of {n} fuzz input object(s):
[
  {{
    "calls": [["functionName", [arg1, arg2], "0x<wei_hex>", "caller_name"], ...],
    "description": "brief description"
  }}
]
JSON only — no markdown, no explanation.

**Example sequence:**
```json
{example}
```

**Recent history for this strategy:**
{history}\
"""
