"""Mutation-mode user prompt template.

Consumed by `fuzzer.mutator.LLMMutator.llm_mutate()`. Mutation-strategy metadata
(goal / technique / value_hints / caller_list / extend_hints / example) is
injected from `llm.strategies.MUTATION_STRATEGY_PROMPTS`.

Placeholders:
  {context}              ABI or whitebox source context (build_contract_context)
  {mutation_strategy}    current RL-selected mutation-strategy name (one of the 7)
  {seed_strategy}        the seed's original strategy (mutation operates on a corpus entry)
  {seed_reward}          seed's recorded reward (for the LLM's situational awareness)
  {initial_balance}      native coin dealt to each test address
  {max_calls_per_item}   per-sequence call cap
  {goal}                 the mutation strategy's objective
  {technique}            the mutation strategy's recipe (boundary values, perturbation factors, …)
  {value_hints}          mutation-strategy-specific ETH/uint hex hints
  {caller_list}          quoted comma-joined caller aliases
  {extend_section}       optional mutation-strategy-specific guidance (or "")
  {arg_encoding}         per-ABI-type argument encoding contract (prompts.common)
  {n}                    requested number of mutated fuzz-input objects
  {seed_json}            the corpus seed serialized as JSON
  {history}              recent run history (formatted by _LLMClient)
"""

MUT_PROMPT_TMPL = """\
{context}

## Mutation task — mutation strategy: {mutation_strategy} (seed strategy: {seed_strategy})

**Objective:** Steer this seed toward a transaction sequence in which the attacker-controlled address (attacker_address) ends up with more total value (native coin + tokens) than it spent — extract funds from the target or break a value invariant in the attacker's favor. Apply the mutation below in service of that goal.

**Context:** All test addresses start with {initial_balance} native coin (ETH/BNB/… by chain). Do not send more native coin per call than this budget allows. Use at most {max_calls_per_item} calls per sequence.

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
Return a JSON array of {n} mutated fuzz input object(s):
[
  {{
    "calls": [...mutated calls...],
    "description": "mut:{mutation_strategy} - brief description"
  }}
]
JSON only — no markdown, no explanation.

**Seed to mutate** (reward={seed_reward:.2f}):
```json
{seed_json}
```

**Recent history for this mutation strategy:**
{history}\
"""
