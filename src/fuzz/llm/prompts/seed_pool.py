"""MADFuzz seed-pool prompt.

Consumed by `baselines.madfuzz.seed_gen.generate_seed_pool()`. The prompt
asks the LLM (called ONCE per run, at startup) to return a JSON array of
FuzzInput seeds; the policy then samples from this pool during hybrid
exploration. See research.md §14 for the MADFuzz design and how this
prompt deviates from the original paper (per-call full-sequence seeds
instead of per-parameter argument variants).

Placeholders:
  {example_json}         in-prompt schema example (see SEED_POOL_EXAMPLE)
  {source_code}          target contract source (after apply_source_budget)
  {max_items}            top-level array cap (LLMConfig.max_items_per_request)
  {max_calls_per_item}   per-sequence call cap
  {arg_encoding}         per-ABI-type argument encoding contract (prompts.common)
"""

SEED_POOL_PROMPT = """You are a smart contract analysis assistant. I will provide you with the Solidity source code of a smart contract. Your task is to analyze the code and return a JSON array of *fuzz input sequences* designed to maximize code coverage and uncover potential vulnerabilities (including reentrancy).

To accomplish this, please think step by step carefully:

1. Read and understand the source code: First, carefully read the entire Solidity smart contract code to understand its structure, purpose, and the role of each function.

2. Identify the functions: For each function in the contract, note the function name, input parameters, and return type (if any). Understand the function's purpose and any conditions or constraints applied to the parameters.

3. Analyze the parameters: For each parameter of each function, consider:
   - Invalid cases: values that could cause the function to revert or behave unexpectedly (e.g., 0x0 addresses, negative numbers when only positive are accepted).
   - Regular, valid cases: typical values within normal operating range.
   - Extreme values: boundaries of the type (0, 1, type-max), including over/underflow candidates.

4. Build attack sequences: Each fuzz input is a *sequence* of calls — not a single function. Produce a diverse set of sequences that includes:
   - Single-call sequences for plain coverage of each function.
   - Multi-step sequences that violate invariants (e.g., inflate a rate/price via a setter, deposit/fund, then withdraw/claim more than was put in — use THIS contract's real function names).
   - **Reentrancy attack sequences** for any function that sends ETH externally before updating state (see step 7).

5. Output format: Return a JSON array of fuzz input objects in **this exact format**:
   [
     {{
       "calls": [["functionName", [arg1, arg2], "0x<wei_hex>", "caller_name"], ...],
       "description": "brief description"
     }}
   ]
   Each call is a 4-element list: [function_name, args_list, value_wei_hex_string, caller_name_string].
   - args_list: argument values matching each ABI parameter type — see "Argument encoding" below.
   - value_wei_hex_string: ETH amount in wei as a hex string (e.g., "0x0" for non-payable, "0xde0b6b3a7640000" for 1 ETH).
   - caller_name_string: must be exactly "attacker_address" (the single attacker identity) — NEVER "deployer_address" and NEVER a raw hex address.

6. Important constraints:
   - Use minimal hex (e.g., "0x0", "0x1", "0xff") — avoid long zero-padded values like "0x0000000000000000000000000000000".
   - Do not use very large values that might cause JSON parsing errors.
   - Use only specific concrete values, not expressions.
   - The output must be a single JSON array — no markdown fences, no commentary outside the JSON.
   - Return **at most {max_items} fuzz input sequence(s)** in the array. Mix single-call coverage seeds with longer attack sequences.
   - Each sequence's `calls` list must contain **at most {max_calls_per_item} call(s)** — keep multi-step exploits within this budget.

7. Reentrancy awareness — **setReentrantCall format**: The attacker re-enters whenever the target calls BACK into it — either by sending it ETH (call{{value:}}, .transfer, .send → receive) or by invoking an unknown selector on it (fallback: ERC777/hook/migration callbacks). Identify functions that make such an outbound callback BEFORE updating internal state (Checks-Effects-Interactions violation), including non-ETH hook callbacks. For each, include at least one fuzz input that arms the unified Attacker via this special FIRST call:
     ["atk.setReentrantCall",
      {{"reentrant_func": "fnName", "reentrant_args": ["0x<hex>", ...], "max_count": N}},
      "0x0",
      "attacker_address"]
   - `reentrant_func` is the function re-called during the callback: the BARE function name on the target contract (e.g., "claimRewards", "withdraw", "transfer") — no parentheses, no argument-type list. Re-entry always targets the main contract, never an external var. The harness builds the Solidity signature locally from the ABI.
   - `reentrant_args` is the list of ABI-encoded arguments matching the function's input types (use [] if the re-entered function is parameterless).
   - `max_count` is the re-entry depth — an integer in [1, 5].
   - There is ONE attacker identity: the arm, all funding/setup calls, AND every trigger call use "attacker_address" as caller so the callback fires with the attacker as msg.sender.

{arg_encoding}

Now, proceed to analyze the provided smart contract code and generate the JSON array as specified.

Example output:
{example_json}

Solidity Smart Contract Code:
{source_code}
"""


# Example output mirrors a known VulnerablePool reentrancy attack: inflate the
# reward rate, deposit twice to accumulate pendingRewards, then call claimRewards
# (which sends ETH before zeroing pendingRewards) — letting the configured
# unified Attacker re-enter claimRewards up to max_count times.
SEED_POOL_EXAMPLE = """[
  {
    "calls": [
      ["atk.setReentrantCall", {"reentrant_func": "claimRewards", "reentrant_args": [], "max_count": 5}, "0x0", "attacker_address"],
      ["setRewardRate", ["0x16345785D8A0000"], "0x0", "attacker_address"],
      ["deposit", [], "0xde0b6b3a7640000", "attacker_address"],
      ["setRewardRate", ["0x3782dace9d90000"], "0x0", "attacker_address"],
      ["deposit", [], "0xde0b6b3a7640000", "attacker_address"],
      ["claimRewards", [], "0x0", "attacker_address"]
    ],
    "description": "Reentrancy attack on claimRewards: configure reentrant callback, inflate rewardRate, deposit ETH twice to accumulate pendingRewards, then call claimRewards which sends ETH before zeroing pendingRewards, allowing the attacker contract to re-enter claimRewards up to 5 times and drain the pool."
  },
  {
    "calls": [["deposit", [], "0xde0b6b3a7640000", "attacker_address"]],
    "description": "Basic coverage: deposit 1 ETH."
  },
  {
    "calls": [["withdraw", ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"], "0x0", "attacker_address"]],
    "description": "Boundary: withdraw uint256.max to probe overflow / underflow."
  }
]"""
