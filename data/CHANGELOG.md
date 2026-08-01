# Changelog — data/ (datasets)

Notable changes to the dataset **layout, schema, and runnable set**. Dates absolute,
newest first. Per-contract exploit mechanics live in each `*_enrich.json`'s `poc`; the
promotion rubric in [`rule/find_data_point.md`](../rule/find_data_point.md).

## [2.15.2] — 2026-07-08 — CompoundTusd source restored → all 25 fork rows fully reliable (no count change)

Finishes the 2.15.1 fork-coverage work: `2022-03_CompoundTusd`'s source tier is no longer
suppressed. The dataset shipped a hand-ported `^0.8.10` rewrite of Compound's original `^0.5.16`
`CErc20Delegate`, so the recompiled artifact could never opcode-match the deployed 0.5.16 impl
(LCP 0.012) → SOURCE line/branch was flagged `coverage_unreliable`. **Fix (data):** re-fetched the
real verified 0.5.16 source of the on-chain implementation `0xa035b9e1…` from Etherscan (V2 API,
12 files, `solc 0.5.16`, optimizer on / 200 runs, `evm=istanbul`) and swapped it in for the port.
Recompiled runtime is now **byte-identical to on-chain (LCP 0.9991)**.
- `raw.json`: `compiler` **v0.8.10 → v0.5.16+commit.9c3226ce**; `source.files` 10 → 12 (adds
  `CarefulMath.sol`, `Exponential.sol`); `provenance.evm_version` **Default → istanbul** (the true
  meaning of "Default" for 0.5.16; istanbul ≥ constantinople so it's safe to pin in the shared
  build — no separate coverage build needed, unlike Bancor). `implementation`/optimizer/runs
  unchanged (already correct from 2.15.1).
- `source/2022-03_CompoundTusd/`: `.sol` files, `abi.json`, `meta.json`, and the per-source
  Etherscan cache all regenerated from the 0.5.16 impl; stale empty `impl.raw.json` removed.
- Verified through the real pipeline (`randomfuzz --verify`): `coverage_unreliable=False`, source
  tier active (branches restored), bc anchored 962. **All 25 DeFiHackLabs fork rows now fully
  reliable** (source + bc + function); none source-suppressed. pytest 425✓.

## [2.15.1] — 2026-07-08 — Fork-coverage fidelity fixes (no count change)

Mostly data-fact fixes (+ one code fix for Bancor) — **same 25+33 runnable rows**; make fork
coverage anchor on the actually-deployed bytecode. 23/25 rows now fully reliable (source + bc +
function); CompoundTusd source stays honestly suppressed (0.8.10 port of a 0.5.16 impl).

- `2024-02_PANDORA` `provenance.optimizer` **false → true** (runs already 200). The mined
  Etherscan flag was wrong: the deployed 9191-byte runtime is optimized, but our recompile
  under `optimizer=false` was 16630 bytes (~2×) → the fork-coverage opcode stream drifted
  (opcode-LCP 0.03) and its SOURCE-tier coverage was suppressed as `coverage_unreliable`.
  With the corrected flag the artifact matches on-chain (LCP 0.998, byte-identical) → PANDORA
  is now a RELIABLE fork-coverage row (source line/branch restored; bc/function unchanged).
- `2020-06_Bancor` **FIXED** (code, not data): its deployed selector dispatcher uses the
  pre-Constantinople `EXP/DIV` form (solc 0.4.26 built-in default EVM = byzantium); the modern
  shared build emits an `SHR` dispatcher → drift (LCP 0.001). A global `evm_version=byzantium`
  can't be used because it's per-`forge build` and forge-std's `shl` safeconsole needs
  constantinople. Fix: `FoundryFuzzer.compile()` now does a SEPARATE target-only coverage build
  (`--skip 'test/*' --evm-version byzantium --out out_cov`) for pre-Constantinople targets — the
  harness build stays modern, forge-std is never compiled under byzantium. Bancor → LCP 0.999,
  RELIABLE (source restored). Only solc < 0.5.5 rows (BEC already reliable, Bancor) trigger the
  extra build (`ForkConfig.coverage_evm_version` / `scaffold._coverage_evm_override`).
- `2022-03_CompoundTusd` `provenance.implementation` **0x3363bae2… → 0xa035b9e1…**. The
  mined impl address has ZERO code at the fork block (14266479); the CToken delegator
  (`CErc20Delegator`, non-EIP-1967 — plain `implementation` storage var) actually delegates
  to `0xa035b9e1…` (`implementation()` @block, 21982 B). With the wrong empty address the
  pipeline couldn't fetch on-chain code → bc/function coverage fell back to the artifact's
  229 JUMPIs (meaningless, since the fork executes the deployed impl); corrected → anchored
  on the real impl's **481 JUMPIs** (bc denom 458 → 962). SOURCE tier stays
  `coverage_unreliable`: the dataset's `CErc20Delegate.sol` is a **`^0.8.10` port** of
  Compound's original `^0.5.16` contract (needed to compile against modern forge-std), so
  the artifact can never opcode-match the deployed 0.5.16 impl (LCP 0.012) — inherent, not
  a data error. (The row's `evm_version` is also mis-mined `Default` vs the real `istanbul`,
  but that only affects the suppressed artifact build, so it's left as-is.)

## [2.15.0] — 2026-07-04 — Unified attacker identity + caller/sentinel rename (no count change)

Refactor only — **same 25+33 runnable rows, all still reproduced**; no schema/layout change.

- The two-actor attacker (EOA `attacker_address` + separate `ReentrancyAttacker` at
  `reentrancy_address`) collapsed into ONE extensible `Attacker` contract deployed at
  `attacker_address`. Every `enrich.json` `poc.calls` caller `"reentrancy_address"` → `"attacker_address"`,
  and the reentrancy setup sentinel head `"reentrancy.setReentrantCall"` → `"atk.setReentrantCall"`.
- Signal `via` field is now only `direct` (or empty) — the old `via=reentrancy` fold is gone (reentrancy
  profit lands on the single attacker as `attacker_gained ... via=direct`).
- `attacker_address` is now a CONTRACT; its `receive()` gates the reentrancy dispatch on `gasleft()>2300`
  so `.transfer`/`.send` payouts to the attacker are accepted rather than reverting the target tx.
- **5 PoC rows re-authored** where `reentrancy_address` had doubled as a *distinct second address* (not a
  reentrancy caller), which the blind rename would have collapsed into the attacker: smartbugs
  `arithmetic/BECToken`, `arithmetic/token` + defihacklabs `2018-04_BEC` now use a distinct `0x…dEaD`
  counterparty (self-transfer/self-batch would cancel the under/overflow); smartbugs
  `access_control/{mapping_write,arbitrary_location_write_simple}` now pass `attacker_address` (was a
  hardcoded EOA literal) into their uint256 owner-slot write — `foundry.py::_normalize_arg` gained a cast
  for an address alias in a numeric/bytesN slot. All 33 smartbugs + (fork-validated) defihacklabs rows
  still reproduce; the unification additionally **unlocks Templedao** (its exploit needs a contract attacker).

## [2.14.0] — 2026-06-28 — Net-profit oracle (VERITE-style) + signal vocabulary rename (no count change)

Oracle upgrade + signal rename — **same 25+33 runnable rows, all still reproduced** (the rename is
additive on confirmation; detection set unchanged — the bottleneck is generation, not the oracle).

- **New value verdicts (fork only, `tier=high`, FP-free):** `attacker_profit` / `target_loss` =
  net value of ALL holdings (every watched ERC20 + native) priced into the chain numéraire
  (wrapped-native) via slippage-aware on-chain `getAmountsOut`, `> start`. The old per-token balance
  deltas survive as `tier=heuristic` signals.
- **Signal vocabulary** drops asset/actor name suffixes — they are now **line fields**, not suffixes:
  `BUG_SIGNAL: <name> tier=<high|heuristic> [asset=native|erc20] [token=<addr>] amount=<wei> [via=direct|reentrancy]`.
  The 4 names: `attacker_profit` · `attacker_gained` · `target_loss` · `target_drained`. The reentrancy
  contract's gain folds into `attacker_gained via=reentrancy` (no separate `reentrancy_gained_*`).
- **Migration:** every `poc.signals` (25 dhl + 33 smartbugs) and `validation.reference_exploit.logs`
  remapped `*_eth`/`*_erc20`→bare name, `reentrancy_gained_*`→`attacker_gained` (deduped). Validators
  (`validate_pocs.py`, `validate_defihacklabs_bugsignal.py`) + rule signal vocabulary updated to match.
- **API rename (non-dataset):** `FuzzResult.found_bug`→`bug_signal_found`, `new_bug_signals`→
  `new_exploit_path` (the field overclaimed "bug" vs "a financial-impact signal fired"). On-disk run-log
  key `bug_found` / DataFrame column `bug_found_any` are **unchanged** (separate name; analysis schema
  intact → no artifact regeneration).
- Chain numéraire/venue resolved by `block.chainid` (mainnet/bsc/arbitrum/avalanche/base/fantom; all 6
  router↔wrapped pairings verified on-chain). Unknown chain → value verdicts degrade to 0 (heuristics
  still fire); never an over-count.
- **`_portfolioValue` is revert-proof:** token bags come from `balanceOf` on untrusted tokens and can
  report absurd (~2²⁵⁶) values, so every value addition is overflow-guarded (an overflowing token is
  skipped — same 0 a `getAmountsOut` overflow would give). Without this, a checked-arithmetic panic in
  the oracle suppressed ALL signals for the run (caught replaying the experiment corpus: a reward-token
  staking PoC reported a near-max balance). The oracle must always survive to emit.

## [2.13.0] — 2026-06-27 — Removed `supply_inflation` oracle signal (no count change)

Oracle vocabulary only — **same 25 runnable rows, all still reproduced**. The `totalSupply`-growth
invariant (`supply_inflation` signal) was dropped from the harness: across all 58 POCs (both datasets)
it produced **0 marginal detections** — its single firing (`2024-11_Ak1111`) also fired
`attacker_gained_erc20`, and the mintable-target gate silenced it on every public-mint row. A
free/unauthorized mint the attacker keeps still surfaces via `attacker_gained_erc20`.

- **Signal vocabulary** is now ETH + ERC20 gain/drain only: `attacker_gained_eth|erc20` ·
  `reentrancy_gained_eth|erc20` · `target_drained_eth|erc20`. No `supply_inflation`.
- **`2024-11_Ak1111`** — `poc.signals` and `validation.reference_exploit.logs` drop `supply_inflation`
  (now `["attacker_gained_erc20"]`); row stays runnable + reproduced (rule 4 satisfied). Live-fork
  re-validation pending. No other row recorded the signal.
- Harness: removed `_erc20TotalSupply`, the `watchSupply`/`_target_is_mintable` gate, the
  `bug_type="mint"` label, and the 4-arg `_runOracle` back-compat overload (now one 4-arg signature).

## [2.12.0] — 2026-06-21 — Named vars in fork PoCs (callable + data-only externals; no count change)

Representation only — **same 25 runnable rows, identical bug signals** (proven by a from-`enrich`
fork re-run diffed against the pre-change baseline). Fork PoCs no longer hard-code magic on-chain
addresses the LLM could never guess; they reference named `extend.external` vars.

- **`extend.external` generalized**: entry with `abi` = CALLABLE (interface + `address constant`,
  callable as `<var>.<method>`); entry without `abi` = DATA-ONLY (`{var,address}` → just a named
  `address constant` for a victim/holder/LP-pair/token-passed-as-arg). `enrich.schema.json`:
  `interface`/`abi` now optional.
- **11 rows rewritten** to use named vars + `$ret` for balance-derived amounts (Bancor `XBP`+`victim`,
  PLN/TecraSpace token/router/pair vars, cftoken/Snood/PANDORA holders, 98Token/YodlRouter tokens,
  CompoundTusd underlying); MetaDragon's magic addr was the target → `target_address`. The other 14
  rows had no magic addrs (unchanged). Fork `setUp` drops `deployer_address` (target is on-chain).

## [2.11.0] — 2026-06-21 — Normalize the 3-layer split + drop filename prefix (no count change)

Layout/schema only — **zero data changes**: `load_dataset`/`load_all`/`load_raw` return
byte-identical `Contract` records before vs. after (proven by an asdict equality diff over
both datasets). The three layers were heavily redundant (a row's facts smeared across all
three → drift risk, e.g. the 2.10.2 PANDORA repair had to touch all three). Now **normalized**:
each fact lives in exactly ONE layer and the loader re-joins by `id`, so a row is edited in
one place.

- **Files renamed** (folder already names the dataset): `<ds>_raw.json` → `raw.json`,
  `<ds>_manifest.json` → `manifest.json`, `<ds>_enrich.json` → `enrich.json`.
- **manifest** drops `category`/`target_contract` (live in raw); keeps skip/skip_reason/validation
  (the canonical `reference_exploit` home).
- **enrich** is now lean `{id, poc, extend}`: dropped per-row `kind` (envelope), `category`/
  `target_contract`/`compiler`/`source` (raw), `poc.category` (raw), and the derivable
  `extend.{chain,block,target_address,evm_version,optimizer,optimizer_runs,reference_exploit,
  vulnerabilities,loc}`. `extend` now carries ONLY runtime-only keys (`external`/`setup_template`
  | `constructor_args`/`pre_deploy`/`setup_calls`). DeFiHackLabs enrich shrank ~66.5KB→~28KB.
- **Loader** (`schema.py`): `load_dataset` = enrich⋈raw⋈manifest, `load_all` = raw⋈manifest⋈enrich;
  both reconstitute the full `extend`/`poc` so downstream run/eda is untouched. `_dataset_io`
  (validator round-trip), `gen_setup_template`, `restructure_datasets`, schemas, and COMMANDS
  updated to the new names/shape.
- A pre-flight cross-layer consistency check confirmed **0 drift** (every duplicated field
  agreed) before the dedup.
- Gates: pytest 307/4 · 6 layer files JSON-Schema valid · before/after Contract equality
  IDENTICAL · `_dataset_io` load→save round-trip byte-stable · counts unchanged
  (SmartBugs 116/116/33, DeFiHackLabs 86/86/25).

## [2.10.2] — 2026-06-21 — Repair 2 mis-wired runnable rows (no count change)

Both rows were *counted* in the runnable 25 but silently failed at scaffold time (a smoke
run showed only 23/25 actually building). No new rows; runnable stays **25/86** — this
reconciles the metric with reality (effective runnable 23→25). Two scaffolder robustness
fixes ([`src/experiment/run/scaffold.py`](../src/experiment/run/scaffold.py)) unblocked them:

- **`2024-08_YodlRouter`** (was `build_fail`): scoped imports `@uniswap/v3-core/…`,
  `@uniswap/v3-periphery/…` resolve to lib dirs Etherscan flattened to bare names
  (`src/lib/v3-core/`), which the bare-name remap can't satisfy. `_write_remappings` now
  also emits an `@scope/pkg/` remap whenever a `@scope/pkg` import's last component matches
  a `src/lib/` dir. Builds; `transferFee` ABI exposed.
- **`2024-02_PANDORA`** (was `skip` "no target_contract"): half-promoted in 2.9.1 — raw/
  manifest/enrich carried `target_contract:null` + an empty `source` block despite the
  on-disk verified `PandorasNodes404.sol` and a complete `poc`. Wired
  `target_contract=PandorasNodes404`, `compiler=v0.7.6`, `source{files,primary,abi_path}`;
  set `provenance.verified=true` (Etherscan-verified per `meta.json`). solc 0.7.6 also
  rejected the flattened file's 3 SPDX identifiers (Error 3716), so `_normalize_sources`
  now keeps the first SPDX per file and blanks duplicates (line-count preserved). Builds.
- Counts: runnable **25** and total **86** unchanged; raw verified **61→62**, skip_count
  **25→24** (PANDORA was wrongly unverified). manifest usable/skipped and enrich chains
  unchanged (both rows already counted there).
- Confirmed end-to-end via an `sscfuzz` bug-check (not just `prepare()`): both rows now
  build **and run to completion** — YodlRouter ✅ branch-cov 47/490 (9.6%) in 229.5s,
  PANDORA ✅ branch-cov 121/376 (32.2%) in 469.2s. Fuzzer `bugs=0` as expected (sscfuzz is
  the system under test, not the curation gate; the reference PoC still fires
  `attacker_gained_erc20`). Effective runnable **23→25** verified.
- Gates: pytest 307/4 · all 25 DeFiHackLabs + 33 SmartBugs `prepare()` ok · `sscfuzz`
  bug-check runs YodlRouter+PANDORA to completion · 3 layers JSON-Schema valid ·
  `load_dataset`/`load_all` lengths unchanged.

## [2.10.1] — 2026-06-20 — Refined-residual re-survey (+1 Swapos)

- Refined the structural triage to exclude only **foreign** pranks (attacker-only pranks
  are in scope) → 29-PoC clean residual, all read; **exactly one** unlock.
- **+`2023-04_Swapos`** (business_logic, fork mainnet): `SwaposV2Pair.swap`'s K-check
  scales balances by `1e4` vs the reserve product by `1e6` (100× off) → seed 10 wei WETH,
  swap the pair's whole token0 out. Raw `Pair.swap` but in scope (constant `amount0Out`,
  empty `data`, no callback). → `attacker_gained_erc20`.
- Counts: total 85→86, runnable **24→25**; raw verified 60→61; manifest usable 24→25,
  reproduced 53→54.
- Residual exhausted short of 35 — all OUT (skips): GHT (proxy impl unverified), AffineDeFi
  (attacker `createAaveDebt` callback), Bmizapper/UnizenIO2/CowSwap/Paraswap/ODOS/Seneca
  (victim-approval + crafted calldata), SpaceGodzilla/BDEX (computed `amountOut`),
  MulticallWithoutCheck/Velocore (struct args), NowSwap (fallback callback + unverified),
  UFDao (bug split shop + `IDao.burnLp`).

## [2.10.0] — 2026-06-20 — Full ref-tree + flash re-survey (+3, +5 skips)

- Structural re-read of **all 685** ref PoCs (a prior keyword pass over-claimed
  "exhausted"; corrected). Three unlocks, runnable **21→24**:
  - **+`2022-02_TecraSpace`** (price_oracle, mainnet): `TcrToken.burnFrom` has reversed
    allowance indexing → self-approve pool, burn its TCR, `POOL.sync()`, router buy/sell
    round-trip for USDT (`$ret` chains `balanceOf` into the sell). → `attacker_gained_erc20`.
  - **+`2022-10_EFLeverVault`** (price_oracle, mainnet): Balancer `flashLoan` whose
    **receiver is the target vault** needs no attacker callback — a plain declared external.
    deposit cheap → flash inflates `getVirtualPrice` → withdraw inflated. → `attacker_gained_eth`.
    The lone flash row expressible **without** the (twice-reverted) `FlashloanAttacker`; every
    other flash PoC passes `address(this)` as receiver and needs an attacker callback.
  - **+`2024-04_NGFS`** (access_control, bsc): three unprotected calls bootstrap the attacker
    into the proxy/library role, then `reserveMultiSync(self, n)` mints NGFS (SafeMath `.air`
    = addition). Target-only. → `attacker_gained_erc20`.
- Validator now threads `extend.external`/`setup_template` into the FoundryFuzzer (was
  `fork=` only, so it couldn't exercise declared externals — also re-validated PLN).
- **+5 verified-but-out-of-scope skips** (access/callback gates the keyword triage missed):
  HYPR, Visor, YziAIToken, DDC, PHIL. Catalogue 24 usable / 61 skip / 85 total.

## [2.9.2] — 2026-06-19 — supply_inflation gated to fixed-supply targets

- `_runOracle` takes a `watchSupply` **stack** bool (a state var would be rolled back by the
  oracle's own `revertToState`); `FoundryFuzzer._target_is_mintable()` passes `false` for a
  target with a mint path (public `mint*` in ABI or `_?mint` in `--source`). A mintable
  token's `totalSupply` legitimately grows → was a false positive; real theft still fires
  `attacker_gained_erc20` (zero detections lost).
- `poc.signals` updated (BEGO/WXETA/Uerii/Melo/SwarmMarkets/MetaDragon drop `supply_inflation`;
  Ak1111 keeps both — its `_mint` is in an unseen base file). 21/21 re-validated. No count change.

## [2.9.1] — 2026-06-19 — Skip re-survey vs. declared-external (+1 PANDORA)

- Re-surveyed all 58 skips against the 2.9.0 mechanism; one unlock.
- **+`2024-02_PANDORA`** (business_logic, fork): ERC404 broken-allowance `transferFrom`
  (solc 0.7.6 underflow) — a single flat `transferFrom` moves the V2 pair's tokens to a fresh
  attacker (pair = raw-hex arg, target-only). The old "terminal pair.swap not droppable" skip
  is sidestepped: the any-asset oracle credits the gain in the target token. → `attacker_gained_erc20`.
  Runnable **20→21**.
- NOON is PANDORA's lone structural twin but blocked solely by unverified source.

## [2.9.0] — 2026-06-18 — Declared-external calls + output chaining (+1 PLN)

- New fork `extend` runtime fields (general + LLM-drivable, **not** the removed hardcoded
  sentinels):
  - **`external`** — `[{var, interface, address, abi}]`; a call head `"<var>.<method>"`
    renders against `IInterface(<var>)`. Fuzzer registry + `_render_external_decls()`; LLM
    prompt + llama grammar gain the heads (empty ⇒ unchanged).
  - **`setup_template`** — per-sample full template (stamped from `fork.sol.tpl` by
    `gen_setup_template.py`); fuzzer fills only `${calls_code}`.
  - **`$ret<idx>`** arg tokens chain a single return into a later arg; `<var>`/`max`/`now` also.
- Oracle `target_drained_*` + `supply_inflation` are now **main-target-only** (a DEX/LP
  legitimately moves balance during a swap); attacker-gain still scans every asset.
- **+`2024-09_PLN`** (price_oracle): declared WETH+UniV2 ROUTER + `$ret` express
  buy→trip→sell→withdraw. → `attacker_gained_eth`. Runnable **19→20**.

## [2.8.0] — 2026-06-15 — Co-located dependency deploy + wiring (+12 reentrancy)

- New inline `extend` fields (rendered by `FoundryFuzzer._dep_setup_render()`):
  **`pre_deploy`** (deploy a sibling contract from the same source file, bound to
  `_depaddr_<alias>`) and **`setup_calls`** (post-deploy wiring via the target's API).
- Lifts the SmartBugs PrivateBank/Log family (external Log was codeless → `Deposit` reverted):
  **+12** reentrancy promoted, SmartBugs reentrancy 6→18, runnable **21→33**. The 6 misses
  have an independent time/block-lock (out of scope).
- Also: `_dataset_io._RUNTIME_EXTEND_KEYS` round-trips these (fixes a latent lossy split);
  gas-capped oracle ERC20 probe (`staticcall{gas:100000}`) so a deposit-on-fallback target
  no longer OOGs the oracle.

## [2.7.2] — 2026-06-14 — Sourcify fallback in the source fetcher (0 promotions)

- `fetch_defihacklabs_sources.py` tries Etherscan v2, then Sourcify (keyless, multi-chain).
- The 6 unverified-source skips have no source at any provider; Fantom unreachable. **0
  promotions** (stays 19). No layout change.

## [2.7.1] — 2026-06-14 — Local ERC20+supply oracle graft (+3 arithmetic)

- Grafted the fork financial-loss oracle onto `inline.sol.tpl`/`inline_legacy.sol.tpl`, so a
  deployed local target emits the full `…_eth | …_erc20 | supply_inflation` vocabulary.
- **+3 arithmetic**: `token` (underflow mint), `BECToken` (batchOverflow), `tokensalechallenge`
  (payable ctor + overflow). SmartBugs runnable **18→21**. The other 12 arithmetic rows are
  fund-flow-free overflow toys (need an assertion oracle).

## [2.7.0] — 2026-06-14 — Constructor args/value for inline targets

- New inline `extend.constructor_args` (positional, zipped with the ctor ABI; address aliases
  `deployer_address`/`attacker_address` or raw `0x…`) + `extend.constructor_value` (payable
  ctor wei). Rendered by `_constructor_render()`. Schema/harness only, no promotions.

## [2.6.1] — 2026-06-14 — Mine round 4: +0 (exhaustion confirmed)

- Re-scanned the corpus → 53 strict-clean candidates; hand-read the top 17, all out of scope.
  No promotions, no rows added (out-of-scope from the PoC alone — materializing skip rows would
  repeat the round-3 bloat). Stays 19.

## [2.6.0] — 2026-06-14 — Mine round 3: +4 (verified-source only)

- **+4** verified-source single-target promotions (drop a terminal DEX cash-out the oracle
  doesn't need): `Ak1111`, `YodlRouter`, `Pledge`, `Snood`. Runnable **15→19**, total 63→78.
- **Reverted — two dataset-tailoring experiments (do NOT re-introduce):**
  - hand-built ABIs + a source-less `scaffold` path (a runnable entry MUST have verified
    source — the whitebox prompt feeds it); `scaffold.py` fully reverted.
  - a `time.warp`/repeat `foundry.py` primitive serving only Gym_2/SheepFarm (no generator
    emits it); `foundry.py` reverted. Both back to skip.

## [2.5.0] — 2026-06-14 — Mine round 2: +6

- **+6** verified-source target-only: `BEC`, `Bancor`, `SwarmMarkets`, `FlippazOne`,
  `MetaDragon`, `98Token`. Runnable **9→15**, total 50→63.
- Other-chain support: `scaffold.py` `RPC_ENDPOINTS` + fetcher `CHAIN_ID` cover
  fantom/avalanche/arbitrum/polygon/base/optimism (Etherscan v2 ≠ Fantom).
- Detailed skips added (NovaExchange owner-gated, Parity_kill griefing, DAO_SoulMate/landNFT/
  GAX unverified, ReaperFarm Fantom, StarsArena proxy/reentry). Stopped at 15 (user decision:
  no hand-built ABIs for unverified exploits).

## [2.4.0] — 2026-06-14 — Mine broader DeFiHackLabs repo: +4

- Heuristic-scanned all 685 PoCs → 77 strict-clean candidates; **+4** verified-source
  target-only: `Melo`, `cftoken`, `Umbrella`, `CompoundTusd`. Runnable **5→9**, total 42→50.
- Skips with reasons (reference PoC reproduces; harness expressibility is the block):
  SheepFarm (~200 repeats), Gym_2 (needs warp), DaoMaker/KR (unverified).

## [2.3.5] — 2026-06-13 — Asset-split BUG_SIGNALs + supply invariant

- Gain/drain signals now name the asset: `attacker_gained_{eth,erc20}`,
  `reentrancy_gained_{eth,erc20}`, `target_drained_{eth,erc20}` (replacing the ambiguous
  `…_funds`/`target_drained`).
- New `supply_inflation` (a watched token's `totalSupply` grew — unauthorized mint/overflow;
  `_postprocess_result` labels `bug_type="mint"`). Bug reward unchanged (flat +50/run, path-gated).
- `poc.signals` re-validated, not transcribed.

## [2.3.0–2.3.4] — 2026-06-13 — Price-oracle sentinels: built then fully reverted

> Net effect: **nothing ships from this arc.** The hardcoded DeFi-helper sentinels and the
> `FlashloanAttacker` were added (2.3.0) and removed step-by-step (2.3.1–2.3.2) for violating
> target-only scope; superseded later by the declared-external mechanism (2.9.0). **Do NOT
> rebuild the `FlashloanAttacker` or `swap.exec`/`call.exec`/`flashloan.exec` sentinels.**

- **2.3.0** — added `swap.exec`/`call.exec`/`flashloan.exec` + `FlashLoanAttacker` +
  `SwapHelper`; promoted PLN + Bamboo (6→8).
- **2.3.1** — removed `FlashLoanAttacker`/`flashloan.exec` (no contract could use it; the real
  flash PoCs need nested/access-gated callbacks).
- **2.3.2** — removed `swap.exec`/`call.exec` (they reached non-target contracts — out of
  scope); de-promoted PLN + Bamboo (8→6). Reverts 2.3.0 entirely.
- **2.3.3** — trimmed unused `ReentrancyAttacker` NFT/1155/777 hooks (re-add returning the
  magic value if a future NFT-reentrancy target needs them).
- **2.3.4** — removed ERC20 pre-seeding (`seed_tokens`); de-promoted `Cover` (6→5) — its BPT
  amount was hand-transcribed from the PoC (answer-key capital). Native-ETH `vm.deal` stays.

## [2.2.0] — 2026-06-12 — Financial-loss oracle (multi-asset, config-free)

- `fork.sol.tpl` oracle measures before/after deltas across native ETH + every ERC20
  auto-discovered from `Transfer` logs + the target address itself (catches internal-accounting
  drains). `snapshotState`/`revertToState` reads post-run-discovered tokens' before-balances;
  the sequence still runs **once** (no differential T→T′). `extend.bug_signal_token` now optional.
- All 6 runnable re-confirmed (FAPEN's `unstake` now correctly fires via the target-as-token watch).

## [2.1.0] — 2026-06-12 — DeFiHackLabs recoveries via fork-harness upgrades

- Added fork-harness ERC20 seeding (`seed_tokens`, removed in 2.3.4) + a callback-capable
  `ReentrancyAttacker` (re-enter trampoline) + `validate_fork_candidate.py`.
- Promoted `Cover` + `Templedao` (4→6). The other 9 "recoverable-looking" skips are genuine
  flash/DEX/multi-contract, not flat single-target.

## [2.0.0] — 2026-06-12 — Symmetric three-file layout

- Refactored both datasets onto per-dataset folders with `source/` + the three-file split
  (`raw` / `manifest` / `enrich`); dataset-specific runtime moved into `extend`.
- `source/` is the single source of truth (SmartBugs source on disk, not inlined).
- `schema.py` gains `load_all`/`load_manifest`/`load_raw` + `Contract.extend`; `load_dataset`
  returns the enrich set. `restructure_datasets.py` (migration) + `_dataset_io.py` (validator
  bridge) added. Pre-refactor JSONs relocated to gitignored `legacy_intermediate/`.
- SmartBugs manifest 116 / enrich 18; DeFiHackLabs manifest 42 / enrich 4.

## [1.x] — pre-2026-06-12 — Unified single-file schema

- Two `*-usable.json` files under one `kind`-discriminated envelope; SmartBugs source inline,
  DeFiHackLabs under `defihacklabs/sources/`.
