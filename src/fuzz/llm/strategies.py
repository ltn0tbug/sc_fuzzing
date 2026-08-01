"""Fuzzing strategy definitions — single source of truth for RL action space.

Each strategy drives three downstream systems:
  prompt        → what the LLM is asked to generate (agent.py)
  reward        → how forge output is scored (reward.py)
  detection     → which console.log markers and assertions signal a bug (foundry.py)

The Solidity test template is chosen by FoundryFuzzer based on mode (fork /
legacy / modern), not by strategy — all 17 strategies share inline.sol.tpl.

There are 17 strategies total, in two families:
  GENERATION_STRATEGIES (7)  — generation-based fuzzing; the LLM creates an input from scratch.
  MUTATION_STRATEGIES   (10) — mutation-based fuzzing; the LLM transforms an existing corpus seed.

Two prompt tables, one per family:
  GENERATION_STRATEGY_PROMPTS — generation strategies (actions 0-6): LLM creates inputs from scratch
  MUTATION_STRATEGY_PROMPTS   — mutation strategies   (actions 7-16): LLM applies one named mutation
                                strategy to an existing corpus seed; RL selects the mutation strategy

Gated-off by default in SScFuzz's `disabled_strategies` blocklist (still defined and
runnable for the full ablation): `arg_address` (action 14, generalized by
`arg_shuffle` which rewrites an argument of ANY type, not only addresses).
`call_swap` (action 15) is active in the default roster.
"""

from typing import TypedDict


class StrategyPrompt(TypedDict):
    # ── LLM prompt fields ────────────────────────────────────────────────────
    goal: str
    technique: str
    example_sequence: str
    value_hints: str
    caller_hints: list[str]  # allowed address alias strings for callers AND address args
    extend_hints: str        # extra guidance for strategy-specific setup fields; "" if unused


# Ordered list of generation-strategy names; index = RL action (0-6)
GENERATION_STRATEGIES: list[str] = [
    "reentrancy_probe",
    "arithmetic_probe",
    "access_control_probe",
    "price_oracle_probe",
    "logic_error_probe",
    "boundary_values",
    "exploration",
]


# Strategy prompts are ABI-pattern-driven, not function-name-driven.
# Examples use UPPERCASE <PLACEHOLDERS> that the LLM must substitute with
# real function names from the target ABI. Concrete names in techniques
# (transfer, withdraw, etc.) are listed as *example name patterns* the
# LLM should look for analogs of in the actual ABI — not as required names.
GENERATION_STRATEGY_PROMPTS: dict[str, StrategyPrompt] = {
    "reentrancy_probe": {
        "goal": "Detect reentrancy vulnerabilities (CEI pattern violations).",
        "technique": (
            "Scan the ABI for functions that SEND ETH OUT to msg.sender (typical name patterns: "
            "withdraw*, claim*, redeem*, unstake*, cashOut*, emergencyWithdraw*, *ETH, *Funds, "
            "harvest*, payout* — but use whatever names this ABI actually has). "
            "Configure attacker reentry on one of those functions, fund the contract via a "
            "PAYABLE function (typical names: deposit*, stake*, mint*, fund*, buy*, contribute*), "
            "then trigger the ETH-sending function so the attacker's receive() callback re-enters. "
            "DO NOT default to the names in the example below — they are placeholders."
        ),
        "example_sequence": (
            "Structural pattern (replace UPPERCASE placeholders with real ABI function names):\n"
            '  [["atk.setReentrantCall", {"reentrant_func": "<ETH_SENDER_FROM_ABI>", "reentrant_args": [], "max_count": 4}, "0x0", "attacker_address"],\n'
            '   ["<PAYABLE_FUNC_FROM_ABI>", [], "0xde0b6b3a7640000", "attacker_address"],\n'
            '   ["<PAYABLE_FUNC_FROM_ABI>", [], "0xde0b6b3a7640000", "attacker_address"],\n'
            '   ["<ETH_SENDER_FROM_ABI>", [], "0x0", "attacker_address"]]'
        ),
        "value_hints": "Use \"0xde0b6b3a7640000\" (1 ETH) for payable calls. Use \"0x0\" for non-payable.",
        "caller_hints": ["attacker_address"],
        "extend_hints": (
            "Use \"atk.setReentrantCall\" as the FIRST call to arm the attacker's re-entry callback: "
            "[\"atk.setReentrantCall\", {\"reentrant_func\": \"fnName\", \"reentrant_args\": [\"0x...\"], \"max_count\": 3}, \"0x0\", \"attacker_address\"]. "
            "The attacker re-enters whenever the target calls BACK into it — either by sending it ETH (receive) "
            "or by invoking an unknown selector on it (fallback: e.g. an ERC777/hook/migration callback) — so this "
            "covers callback-driven reentrancy too, not just native-ETH transfers. "
            "reentrant_func is the function re-called during that callback: a BARE function name from THIS target's ABI "
            "(no parentheses, no type list; re-entry always hits the main contract, never an external var). "
            "reentrant_args matches that function's input types (use [] if no args). max_count is the re-entry depth (1-5). "
            "There is ONE attacker identity: route the arm, the funding/setup AND the final trigger call all through "
            "attacker_address (the unified attacker contract) so the callback fires with the attacker as msg.sender."
        ),
    },
    "arithmetic_probe": {
        "goal": "Detect integer overflow / underflow (wraparound) AND numeric off-by-one / boundary-condition bugs.",
        "technique": (
            "Attack arithmetic two ways in the SAME iteration — spread breadth across MULTIPLE "
            "distinct numeric functions, don't fixate on one.\n"
            "  1. WRAPAROUND (overflow/underflow): unchecked mul/add past 2^256-1, and subtraction "
            "that underflows below 0 (pre-0.8 math or `unchecked{}` blocks). Scan the ABI for "
            "functions taking uint args, especially pure/view helpers that do arithmetic on inputs "
            "(typical name patterns: batch*, compute*, calculate*, quote*, getAmountOut*, convert*, "
            "transfer*, *Reward*). Include any function whose args include a token amount / share / "
            "count value, and subtraction paths like transfer/withdraw that decrement a balance. "
            "For batch*/array functions pass an array-of-large-values (count * value wraps).\n"
            "  2. NUMERIC BOUNDARY / off-by-one: call each numeric function across the boundary "
            "sweep 0, 1, max-1, max, max+1, and any exact require()-threshold value visible in "
            "source (a correct '>=' / '<=' guard rejects one side — probe both). Also test empty "
            "arrays [], single-element arrays, and address(0) (\"0x0\") as a degenerate arg.\n"
            "Full uint boundary pool to draw from: 0, 1, 255 (0xff), 256 (0x100), 65535 (0xffff), "
            "2^64-1, 2^128-1, 2^255 (0x8000…), 2^256-1 (0xffff…ff / uint256 max). "
            "Do NOT chase rounding/precision or division bugs — those are out of scope. "
            "DO NOT default to the names in the example below — they are placeholders."
        ),
        "example_sequence": (
            "Structural pattern (replace UPPERCASE placeholders with real ABI function names — "
            "spread across distinct functions and boundary values):\n"
            '  [["<ARITHMETIC_FUNC_FROM_ABI>", ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0x2"], "0x0", "attacker_address"],\n'
            '   ["<NUMERIC_ARG_FUNC_FROM_ABI>", ["0x0"], "0x0", "attacker_address"],\n'
            '   ["<NUMERIC_ARG_FUNC_FROM_ABI>", ["0x1"], "0x0", "attacker_address"]]'
        ),
        "value_hints": "Use \"0x0\", \"0x1\", \"0xff\", \"0xffff\", \"0xffffffff\", \"0x8000000000000000000000000000000000000000000000000000000000000000\" (2^255), \"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\" (uint256 max), and values just above/below key require() thresholds. For collection args use [] or a single-element list.",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "access_control_probe": {
        "goal": "Find missing access control, owner bypasses, and unprotected token issuance.",
        "technique": (
            "Scan the ABI for STATE-MUTATING functions whose names suggest privileged operations "
            "(typical name patterns: set*, change*, update*, upgrade*, transferOwnership*, "
            "renounce*, pause*, unpause*, emergency*, drain*, rescue*, sweep*, withdraw*, "
            "mint*, burn*, initialize*, init* — but use whatever this ABI actually has). "
            "Call ALL such functions from attacker_address (an unprivileged caller) — if any "
            "succeeds without reverting on auth, that's an access-control bug. Three high-yield "
            "sub-cases to ALWAYS try:\n"
            "  1. SELF-PROMOTION: for address-type arguments pass attacker_address itself "
            "(addOwner/setOwner/addMinter/grantRole(attacker)), or address(0).\n"
            "  2. UNPROTECTED MINT: call mint*/mintTo* with attacker_address as the recipient and "
            "a large amount — the witness is the attacker's token balance rising from zero.\n"
            "  3. SIGNATURE / INITIALIZER BYPASS: many mints are 'guarded' by a signature or proof "
            "check that is trivially passed — supply EMPTY values for those args (empty bytes \"0x\", "
            "empty arrays []), and call initialize*/init* directly even on an already-live contract "
            "to seize the mint/owner role.\n"
            "Prefer breadth: try every suspicious setter and every mint/initialize path, not just "
            "the most obvious one. DO NOT default to the names in the example below."
        ),
        "example_sequence": (
            "Structural pattern (replace UPPERCASE placeholders with real ABI function names):\n"
            '  [["<UNPROTECTED_INIT_OR_SETTER_FROM_ABI>", [<empty-or-attacker-args>], "0x0", "attacker_address"],\n'
            '   ["<MINT_FUNC_FROM_ABI>", ["attacker_address", "0x3635c9adc5dea00000"], "0x0", "attacker_address"]]'
        ),
        "value_hints": "Use \"0x0\" for amounts, or \"0x3635c9adc5dea00000\" (large) for mint amounts. For address params, use attacker_address (self) / target_address / address(0) (\"0x0\") or 40-hex-digit raw addresses. For signature/proof args use empty bytes \"0x\" or empty arrays [].",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "price_oracle_probe": {
        "goal": "Detect price-oracle manipulation and share-pricing / token-accounting attacks.",
        "technique": (
            "Target functions that DERIVE A VALUE from contract state that an attacker can move. "
            "Two common shapes in THIS ABI:\n"
            "  (a) READ-SIDE share pricing: a function that prices shares/assets from a live ratio "
            "(typical names: getVirtualPrice*, getPricePerShare*, convertToAssets*, convertToShares*, "
            "*PerShare*, exchangeRate*, get*Price, quote*). Move the underlying balance/reserve first "
            "(deposit/donate/transfer tokens straight to the contract, sync*, skim*), then mint/redeem "
            "shares so the stale-vs-fresh ratio pays out more than was put in.\n"
            "  (b) STATEFUL TOKEN HOOK: an ERC20 transfer*/transferFrom*/burnFrom* whose accounting is "
            "broken — e.g. a side effect that mints/credits the caller, or an allowance check that is "
            "REVERSED or indexed wrong. Call it directly as the attacker and watch for balance gained "
            "without payment.\n"
            "Build the sequence: skew the state, then call the value-deriving function and extract. "
            "DO NOT default to the names in the example below — find the analogs in THIS ABI."
        ),
        "example_sequence": (
            "Structural pattern (replace UPPERCASE placeholders with real ABI function names):\n"
            '  [["<BALANCE_OR_RESERVE_SKEW_FROM_ABI>", ["0x3635c9adc5dea00000"], "0x0", "attacker_address"],\n'
            '   ["<SHARE_PRICE_READER_OR_REDEEM_FROM_ABI>", [], "0x0", "attacker_address"],\n'
            '   ["<EXTRACT_FUNC_FROM_ABI>", [], "0x0", "attacker_address"]]'
        ),
        "value_hints": "Use \"0x3635c9adc5dea00000\" (1000 ETH) and larger to skew balances/reserves at scale; \"0x0\" for non-payable reads.",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "logic_error_probe": {
        "goal": "Find broken-invariant and faulty-accounting logic errors.",
        "technique": (
            "Hunt for functions that MOVE FUNDS OR SHARES based on a check that may be wrong, missing, "
            "or inverted. High-yield patterns in THIS ABI:\n"
            "  1. NON-PARTICIPANT WITHDRAW: call withdraw*/unstake*/redeem*/claim* as an account that "
            "NEVER deposited or staked — a bad balance check (or an underflow on a zero balance) can "
            "still pay out or corrupt accounting.\n"
            "  2. INVERTED / WRONG GUARD: try threshold args that a correct '>=' / '<=' would reject "
            "(e.g. amount == balance, amount just over balance) to expose inverted comparisons.\n"
            "  3. BROKEN INVARIANT: for pool/AMM-style targets, drive swap*/skim*/sync* so a "
            "constant-product (K) or reserve invariant is checked AFTER the imbalance, not before.\n"
            "  4. ORDER-DEPENDENT STATE: sequence setter→action→setter→action, init-after-use, "
            "deposit-after-withdraw, to reach states the developer didn't anticipate.\n"
            "The witness is value gained without legitimate entitlement. DO NOT default to the names "
            "in the example below."
        ),
        "example_sequence": (
            "Structural pattern (replace UPPERCASE placeholders with real ABI function names):\n"
            '  [["<WITHDRAW_OR_UNSTAKE_FROM_ABI>", ["0xde0b6b3a7640000"], "0x0", "attacker_address"],\n'
            '   ["<SWAP_OR_ACTION_FUNC_FROM_ABI>", ["0x0", "0xde0b6b3a7640000"], "0x0", "attacker_address"],\n'
            '   ["<DEPENDENT_EXTRACTOR_FROM_ABI>", [], "0x0", "attacker_address"]]'
        ),
        "value_hints": "Use moderate hex values like \"0x64\", \"0x3e8\" for state changes. Use large values like \"0xde0b6b3a7640000\" for deposits/withdraw amounts. Try amounts at or just above a balance to hit inverted guards.",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "boundary_values": {
        "goal": "Find off-by-one errors and boundary condition bugs.",
        "technique": (
            "Pick functions from the ABI that take numeric args (uint/int) and call each with "
            "boundary values: 0, 1, max-1, max, max+1, exact require()-threshold values if "
            "visible in source. Also test empty arrays, single-element arrays, address(0). "
            "Spread across MULTIPLE distinct functions per iteration — don't fixate on one. "
            "DO NOT default to the names in the example below."
        ),
        "example_sequence": (
            "Structural pattern (replace UPPERCASE placeholders with real ABI function names):\n"
            '  [["<PAYABLE_FUNC_FROM_ABI>", [], "0x1", "attacker_address"],\n'
            '   ["<NUMERIC_ARG_FUNC_FROM_ABI>", ["0x0"], "0x0", "attacker_address"],\n'
            '   ["<NUMERIC_ARG_FUNC_FROM_ABI>", ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"], "0x0", "attacker_address"]]'
        ),
        "value_hints": "Use \"0x0\", \"0x1\", \"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\" and values just above/below key thresholds.",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "exploration": {
        "goal": "Pure breadth-first ABI exploration — call as many distinct functions as possible.",
        "technique": (
            "This strategy has NO attack framing. The single objective is to maximize the number "
            "of DISTINCT function names called in this sequence.\n"
            "Steps:\n"
            "  1. List every function in the ABI above.\n"
            "  2. Pick UP TO 10 functions you have not called recently (see history).\n"
            "  3. Emit one call per function, in any order, with valid args matching its input types.\n"
            "  4. Do NOT repeat function names within this sequence.\n"
            "  5. Do NOT skip a function because its name 'looks uninteresting' — getters, views, "
            "and admin functions all count. Coverage comes from breadth, not depth.\n"
            "Use simple valid args: \"0x0\" or small hex for uints, \"attacker_address\" for addresses, "
            "[] for empty arrays. value=\"0xde0b6b3a7640000\" for payable, \"0x0\" otherwise."
        ),
        "example_sequence": (
            "Structural pattern (substitute every UPPERCASE placeholder with a DIFFERENT real ABI "
            "function name — each entry must be a distinct function):\n"
            '  [["<ABI_FUNC_1>", [<valid_args>], "0x0", "attacker_address"],\n'
            '   ["<ABI_FUNC_2>", [<valid_args>], "0x0", "attacker_address"],\n'
            '   ["<ABI_FUNC_3>", [], "0xde0b6b3a7640000", "attacker_address"],\n'
            '   ["<ABI_FUNC_4>", [<valid_args>], "0x0", "attacker_address"],\n'
            '   ["<ABI_FUNC_5>", [<valid_args>], "0x0", "attacker_address"]]'
        ),
        "value_hints": "Use \"0x0\" for non-payable, \"0xde0b6b3a7640000\" (1 ETH) for payable. Use \"0x0\" or small hex for numeric args.",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
}


# Ordered list of mutation-strategy names; index = RL mutation action offset (action_idx - 7)
MUTATION_STRATEGIES: list[str] = [
    "value_perturb",   # action 7
    "arg_boundary",    # action 8
    "caller_swap",     # action 9
    "call_insert",     # action 10
    "call_delete",     # action 11
    "call_shuffle",    # action 12
    "reentry_depth",   # action 13
    "arg_address",     # action 14 (gated off by default — generalized by arg_shuffle)
    "call_swap",       # action 15 (active: call substitution)
    "arg_shuffle",     # action 16 (any-type arg rewrite; replaces arg_address in the active roster)
]


# ── Mutation-strategy prompts (actions 7-16) ─────────────────────────────────
# One entry per mutation strategy.  RL selects the mutation strategy; the LLM is told exactly
# which mutation technique to apply to the seed.

MUTATION_STRATEGY_PROMPTS: dict[str, StrategyPrompt] = {
    "value_perturb": {
        "goal": "Scale ETH amounts on payable calls to probe value-sensitive code paths and unlock underpriced attack angles.",
        "technique": (
            "Choose one payable call in the seed and multiply its ETH value by a factor:\n"
            "  0× (set to 0 wei), 0.1×, 0.5×, 1.5×, 2×, or 10×.\n"
            "- If value is already 0 on a payable call, treat 1 ETH (\"0xde0b6b3a7640000\") as the baseline before scaling.\n"
            "- If the seed has a very large value, also try reducing it — some checks trigger only below a threshold.\n"
            "- Produce variants at multiple scales so coverage spans the value-sensitive range."
        ),
        "example_sequence": '[["deposit", [], "0x1bc16d674ec80000", "attacker_address"], ["claimRewards", [], "0x0", "attacker_address"]]',
        "value_hints": "Use \"0x0\", \"0xde0b6b3a7640000\" (1 ETH), \"0x1bc16d674ec80000\" (2 ETH), \"0x8ac7230489e80000\" (10 ETH), \"0x3635c9adc5dea00000\" (1000 ETH).",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "arg_boundary": {
        "goal": "Replace one argument with a boundary or degenerate value to trigger overflow, underflow, off-by-one, or empty-collection conditions.",
        "technique": (
            "Pick one non-address argument in the seed and replace it with an edge value:\n"
            "- NUMERIC arg → one boundary value: 0, 1, 255 (0xff), 256 (0x100), 65535 (0xffff),\n"
            "  4294967295 (0xffffffff), 2^64-1 (0xffffffffffffffff), 2^128-1, 2^255-1,\n"
            "  2^256-1 (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff).\n"
            "- ARRAY arg → a degenerate collection: empty [] or a single-element list. Empty arrays\n"
            "  expose length-underflow and signature-array bypasses; long arrays expose loop overflows.\n"
            "- BYTES arg → empty bytes \"0x\" (bypasses many signature/proof checks that don't validate length).\n"
            "- Each variant should test a different edge — they hit different paths.\n"
            "- Never replace an ADDRESS-type argument here — that is the arg_address mutation's job.\n"
            "- If no eligible args exist, copy the seed unchanged and change one ETH value to 0 or max."
        ),
        "example_sequence": '[["withdraw", ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"], "0x0", "attacker_address"]]',
        "value_hints": "Use \"0x0\", \"0x1\", \"0xff\", \"0xffff\", \"0xffffffff\", \"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\" (uint256 max). For collection args use [] or \"0x\".",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "arg_address": {
        "goal": "Rewrite one address-typed argument to expose self-promotion, unprotected-mint-recipient, and cross-account bugs.",
        "technique": (
            "Find an address-typed argument in the seed (a recipient, owner, minter, spender, or role "
            "target) and replace it with a different alias to redirect the operation toward the attacker:\n"
            "  attacker_address  — self-promotion / mint-to-self (setOwner, addMinter, mint, transfer to attacker);\n"
            "  target_address    — the contract itself (e.g. ERC404 transfer-to-token triggers a mint);\n"
            "  \"0x0000000000000000000000000000000000000000\" — the zero address (burn / unguarded sink).\n"
            "- Prefer arguments on privileged or token-moving calls (mint*, setOwner*, addMinter*, grantRole*, transfer*).\n"
            "- Change exactly one address argument per variant; keep numeric args and ETH values unchanged.\n"
            "- If the seed has no address-typed argument, copy it unchanged."
        ),
        "example_sequence": '[["mint", ["attacker_address", "0x3635c9adc5dea00000"], "0x0", "attacker_address"]]',
        "value_hints": "Keep original numeric/ETH values. Address args: \"attacker_address\", \"target_address\", or \"0x0000000000000000000000000000000000000000\".",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "caller_swap": {
        "goal": "Re-target which call executes as the attacker to expose unauthorized-access / cross-account state bugs.",
        "technique": (
            "There is now a SINGLE attacker identity (attacker_address, the unified attacker contract), so "
            "every call already runs as the attacker — there is no second caller alias to swap to.\n"
            "- The only valid caller alias is attacker_address; keep it on every call.\n"
            "- Any caller here is unauthorized relative to the deployer — that is intentional (privileged "
            "setXxx / emergencyXxx / transferOwnership calls made by the attacker probe access control).\n"
            "- With no alternate caller, apply a MINIMAL structural nudge instead: copy the seed and, if it "
            "helps reach a privileged path, move an administrative call (setXxx, emergencyXxx) earlier or "
            "later in the sequence; otherwise return the seed unchanged."
        ),
        "example_sequence": '[["setRewardRate", ["0xde0b6b3a7640000"], "0x0", "attacker_address"], ["emergencyWithdraw", [], "0x0", "attacker_address"]]',
        "value_hints": "Use \"0x0\" for non-payable calls. Keep original ETH values on payable calls.",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "call_insert": {
        "goal": "Insert a call to a function not already in the seed to expand coverage and reveal new exploit paths.",
        "technique": (
            "Add one call to a function that does NOT already appear in the seed:\n"
            "- Insert it after any setup entries and before or after existing attack calls.\n"
            "- Choose a function related to the seed's vulnerability class:\n"
            "  reentrancy → add deposit or setRewardRate;\n"
            "  access-control → add a privileged setter (setRewardRate, emergencyWithdraw);\n"
            "  arithmetic → add a pure helper with extreme args (computeReward, earlyWithdrawFee).\n"
            "- Provide valid argument types as inferred from the ABI.\n"
            "- Try different insertion positions across variants.\n"
            "- REENTRANCY ARMING: if the seed is NOT already a reentrancy attempt (no "
            "\"atk.setReentrantCall\" entry), you MAY convert it into one by INSERTING that "
            "setup call at position 0 — "
            "[\"atk.setReentrantCall\", {\"reentrant_func\": \"<ETH_SENDER_FROM_ABI>\", "
            "\"reentrant_args\": [], \"max_count\": 3}, \"0x0\", \"attacker_address\"] — pointing "
            "reentrant_func at a bare ETH-sending function in the seed, and re-route the seed's calls "
            "through attacker_address. This turns a benign seed into a reentrancy probe for free.\n"
            "- MAX-LENGTH SUBSTITUTION: if the seed is ALREADY at the maximum sequence length, do "
            "NOT skip the insert — instead REMOVE one existing (non-setup) call and insert your new "
            "call in its place, so the sequence length stays within the cap. This gives you "
            "call-substitution behavior at the length boundary."
        ),
        "example_sequence": '[["setRewardRate", ["0xde0b6b3a7640000"], "0x0", "attacker_address"], ["deposit", [], "0xde0b6b3a7640000", "attacker_address"], ["claimRewards", [], "0x0", "attacker_address"]]',
        "value_hints": "Use \"0x0\" for non-payable, \"0xde0b6b3a7640000\" (1 ETH) for payable inserts.",
        "caller_hints": ["attacker_address"],
        "extend_hints": (
            "If the seed already contains \"atk.setReentrantCall\", keep it at position 0 and "
            "insert new attack calls after it. If it does NOT and the seed sends ETH out, you may "
            "ARM reentrancy by inserting a \"atk.setReentrantCall\" entry at position 0 "
            "(reentrant_func = a bare ETH-sending function from THIS target's ABI, max_count 1-5) "
            "and routing the calls through attacker_address. At max sequence length, delete one "
            "existing call before inserting so the length cap is respected. "
            "New payable calls using ETH callbacks should use attacker_address as caller."
        ),
    },
    "call_delete": {
        "goal": "Remove one call to find the minimal trigger sequence and expose simpler exploit paths.",
        "technique": (
            "Remove exactly one non-setup call from the seed:\n"
            "- Try removing each regular call in a separate variant to discover which calls are essential.\n"
            "- Always keep at least one regular call.\n"
            "- Shorter sequences can bypass length-based guards or reveal bare precondition bugs."
        ),
        "example_sequence": '[["deposit", [], "0xde0b6b3a7640000", "attacker_address"], ["claimRewards", [], "0x0", "attacker_address"]]',
        "value_hints": "Keep the original ETH values and arguments of the remaining calls unchanged.",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "call_shuffle": {
        "goal": "Reorder calls to trigger order-dependent state bugs and reveal sequence-sensitive vulnerabilities.",
        "technique": (
            "Permute the order of non-setup calls to produce a different execution sequence:\n"
            "- Keep any \"atk.setReentrantCall\" entry at position 0 — never reorder it.\n"
            "- Try placing claim/withdraw calls BEFORE deposit to hit unchecked preconditions.\n"
            "- Try placing state-setters (setRewardRate) AFTER state-readers (claimRewards) to expose staleness.\n"
            "- Each variant should use a meaningfully different order, not just swap two adjacent calls."
        ),
        "example_sequence": '[["claimRewards", [], "0x0", "attacker_address"], ["deposit", [], "0xde0b6b3a7640000", "attacker_address"], ["claimRewards", [], "0x0", "attacker_address"]]',
        "value_hints": "Keep the original ETH values and arguments; only change call order.",
        "caller_hints": ["attacker_address"],
        "extend_hints": (
            "If the seed contains \"atk.setReentrantCall\", it must remain as the first entry. "
            "Only reorder the regular attack calls that follow it."
        ),
    },
    "reentry_depth": {
        "goal": "Adjust re-entry depth to drain more ETH per callback chain or escape re-entrancy guards.",
        "technique": (
            "Modify the max_count in the \"atk.setReentrantCall\" entry:\n"
            "- Increase by 1–2 to drain more ETH per callback chain (more recursive calls before reverting).\n"
            "- Decrease by 1–2 to sometimes bypass per-call gas limits that prevent deep re-entry.\n"
            "- Clamp to [1, 5] — values outside this range are invalid.\n"
            "- If the seed has no \"atk.setReentrantCall\", add one targeting the most ETH-sending function "
            "(e.g. claimRewards, withdraw) with max_count=4 as the FIRST call."
        ),
        "example_sequence": (
            '[["atk.setReentrantCall", {"reentrant_func": "claimRewards", "reentrant_args": [], "max_count": 5}, "0x0", "attacker_address"], '
            '["deposit", [], "0xde0b6b3a7640000", "attacker_address"], '
            '["claimRewards", [], "0x0", "attacker_address"]]'
        ),
        "value_hints": "Use \"0xde0b6b3a7640000\" (1 ETH) or larger for payable calls. Use \"0x0\" for non-payable.",
        "caller_hints": ["attacker_address"],
        "extend_hints": (
            "The \"atk.setReentrantCall\" entry configures the unified Attacker's reentrancy callback. "
            "Format: [\"atk.setReentrantCall\", {\"reentrant_func\": \"fnName\", \"reentrant_args\": [\"0x...\"], \"max_count\": N}, \"0x0\", \"attacker_address\"]. "
            "The attacker re-enters when the target calls back into it — sending it ETH (receive) or hitting an unknown "
            "selector on it (fallback: ERC777/hook/migration callbacks), so callback-driven reentrancy works too. "
            "reentrant_func is the BARE function name on the target contract (no parentheses; re-entry always hits the "
            "main contract, never an external var) — the harness builds the Solidity signature from the ABI. "
            "max_count is the re-entry depth (1–5). "
            "Route all attack calls through attacker_address so the callback fires with the attacker as msg.sender."
        ),
    },
    "call_swap": {
        "goal": "Substitute one call with a call to a DIFFERENT ABI function, keeping the sequence length and structure.",
        "technique": (
            "Pick one non-setup call in the seed and REPLACE it with a call to a different function "
            "from the ABI — same position, same sequence length (distinct from call_insert=add and "
            "call_delete=remove; this is the only mutation that changes the *function* itself):\n"
            "- Choose a replacement related to the seed's vulnerability class or an unexplored neighbor "
            "(a sibling setter, an alternate withdraw/redeem path, a different arithmetic helper).\n"
            "- Provide valid argument types for the NEW function as inferred from the ABI.\n"
            "- Keep the original ETH value if the new function is non-payable; supply a payable value if it is.\n"
            "- Keep any \"atk.setReentrantCall\" entry at position 0 — never swap it.\n"
            "- Try swapping at different positions across variants."
        ),
        "example_sequence": '[["deposit", [], "0xde0b6b3a7640000", "attacker_address"], ["emergencyWithdraw", [], "0x0", "attacker_address"]]',
        "value_hints": "Keep the original ETH value on a non-payable swap; use \"0xde0b6b3a7640000\" (1 ETH) for a payable replacement. Use \"0x0\" for non-payable.",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
    "arg_shuffle": {
        "goal": "Rewrite ONE argument of ANY type with a boundary / degenerate / redirected value — a general single-argument mutation across every arg kind.",
        "technique": (
            "Pick one non-setup call and replace exactly one of its arguments, choosing the edit by the "
            "argument's type (this generalizes address-only redirection to every argument kind):\n"
            "  ADDRESS → a different alias to redirect the operation: attacker_address (self-promotion / "
            "mint-to-self), target_address (contract-as-recipient, e.g. ERC404 transfer-to-token mint), "
            "or \"0x0000000000000000000000000000000000000000\" (burn / unguarded sink).\n"
            "  NUMERIC (uint/int) → a boundary value: 0, 1, 255 (0xff), 65535 (0xffff), 2^64-1, 2^128-1, "
            "2^255-1, 2^256-1 (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff).\n"
            "  BYTES → empty bytes \"0x\" (bypasses length-naive signature/proof checks).\n"
            "  ARRAY → a degenerate collection: empty [] or a single element.\n"
            "  BOOL → the flipped value.\n"
            "- Prefer arguments on privileged or value-moving calls (mint*, setOwner*, transfer*, "
            "withdraw*), but any argument is fair game.\n"
            "- Change exactly one argument per variant; keep the ETH value and caller unchanged.\n"
            "- If the seed has no arguments, copy it unchanged."
        ),
        "example_sequence": '[["mint", ["attacker_address", "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"], "0x0", "attacker_address"]]',
        "value_hints": "Address args: \"attacker_address\", \"target_address\", \"0x0000000000000000000000000000000000000000\". Numeric args: \"0x0\", \"0x1\", \"0xff\", \"0xffff\", \"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\". Collections: [] or \"0x\". Keep original ETH values.",
        "caller_hints": ["attacker_address"],
        "extend_hints": "",
    },
}


