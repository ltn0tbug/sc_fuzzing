// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Shared harness for ALL three generated test modes (fork / inline / inline_legacy).
//
// The per-test file (rendered from fork.sol.tpl / inline.sol.tpl /
// inline_legacy.sol.tpl) does `import "./Harness.sol";` and declares
// `contract FuzzInputTest is SCFuzzHarness { … }`. It is written next to the test
// by FoundryFuzzer (and the fork validator) so the relative import resolves.
//
// This file is the SINGLE SOURCE of the callback-capable attacker + the
// financial-loss oracle. Editing the oracle here updates every mode at once — the
// reason the three templates no longer each carry their own ~110-line copy.
// ─────────────────────────────────────────────────────────────────────────────

// Unified, extensible attacker contract. This is the SINGLE attacker identity —
// deployed at `attacker_address` in every template's setUp — so funding, arming and
// triggering an exploit all flow through one address (no split-identity trap).
//
// A callback the target invokes on this contract (native `receive`, or any
// unknown-selector call via `fallback(bytes)` — e.g. a target-specific
// migration/hook callback) routes to `_dispatch`, which fans out to the ACTIVE
// exploit module selected by `mode`. Reentrancy is the only live module today;
// `setFlashloanCall` is a documented stub (extension slot, no behavior this phase).
// Silently no-ops when unconfigured (Mode.NONE) — e.g. a plain token/ETH transfer
// in during a non-reentrancy run — instead of reverting.
contract Attacker {
    enum Mode { NONE, REENTRANCY, FLASHLOAN }
    Mode public mode;

    address target;

    // REENTRANCY module state.
    uint256 count;
    uint256 maxCount;
    bytes reentrantCalldata;

    // Bytes returned from fallback(bytes) (default empty). Lets a target that
    // consumes the callback's return value keep executing.
    bytes returnData;

    // FLASHLOAN module state (stub — recorded but unused this phase).
    address flashProvider;
    bytes flashCalldata;

    constructor(address _target) { target = _target; }

    // Arm the REENTRANCY module: on each callback the target makes to this contract,
    // re-enter `target` with `data`, up to `_maxCount` times.
    function setReentrantCall(bytes memory data, uint256 _maxCount) external {
        require(data.length > 0, "empty calldata");
        require(_maxCount > 0, "maxCount must be > 0");
        reentrantCalldata = data;
        maxCount = _maxCount;
        mode = Mode.REENTRANCY;
    }

    // Optional bytes returned from fallback(bytes) callbacks (default empty).
    function setReturnData(bytes memory data) external { returnData = data; }

    // STUB — the flashloan module is NOT implemented this phase. Records intent and
    // switches mode; `_handleFlashloan` is a documented no-op (extension slot).
    function setFlashloanCall(address provider, bytes memory data) external {
        flashProvider = provider;
        flashCalldata = data;
        mode = Mode.FLASHLOAN;
    }

    // Route an inbound callback to the active module.
    function _dispatch() internal {
        if (mode == Mode.REENTRANCY) { _reenter(); }
        else if (mode == Mode.FLASHLOAN) { _handleFlashloan(); }
    }

    function _reenter() internal {
        if (count < maxCount) {
            count++;
            (bool s,) = target.call(reentrantCalldata);
            if (!s) { return; }
        }
    }

    // TODO(flashloan phase): initiate/handle a flashloan against `flashProvider`
    // with `flashCalldata`. No-op stub for now — kept so the dispatch/extension
    // wiring is exercised and a future module drops in here.
    function _handleFlashloan() internal {}

    // Because attacker_address is now a CONTRACT (not an EOA), a target that pays
    // the attacker via `.transfer`/`.send` forwards only the 2300-gas stipend — too
    // little to run `_dispatch` (a cold SLOAD of `mode` alone exceeds it) and, more
    // importantly, too little to re-enter at all. So dispatch only when a real
    // `.call` forwarded ample gas; otherwise just accept the ETH. This preserves
    // native-ETH reentrancy (exploitable targets use `.call{value:}` → full gas)
    // while letting the unified attacker receive `.transfer`/`.send` payouts without
    // reverting the target's transaction.
    receive() external payable {
        if (gasleft() > 2300) { _dispatch(); }
    }
    fallback(bytes calldata) external payable returns (bytes memory) {
        _dispatch();
        return returnData;
    }
}

// Financial-loss oracle base. The derived test contract sets target_address /
// attacker_address (the unified Attacker) / deployer_address in its setUp, then wraps
// the fuzz sequence in `_beginOracle(); <calls>; _runOracle();` — both take no actor
// arguments (the addresses are harness state) and no balances (all "before" reads happen
// after the rewind inside _runOracle).
abstract contract SCFuzzHarness is Test {
    address target_address;
    address attacker_address;
    address deployer_address;
    Attacker attacker;

    // Selects the pricing venue for the tier=high value verdicts (NOT whether they fire —
    // they run in all modes). true → the real on-chain DEX resolved by block.chainid (the
    // fork template sets this in setUp); false (inline/legacy default) → the mock/empty
    // DEX in `_pricingVenue`, which prices native 1:1 and every token at 0, so a native
    // net profit still proves the high tier without any real DEX.
    bool forkMode;

    // Pre-call state snapshot id, set by _beginOracle() and consumed by _runOracle().
    // Kept on the harness (not threaded through the test body) so the generated test's
    // fuzz function is just `_beginOracle(); <calls>; _runOracle();` — no oracle
    // bookkeeping leaks into the per-mode templates.
    uint256 _snapId;

    // Arm the oracle immediately before the fuzz call sequence: start recording logs
    // (for post-run ERC20 discovery) and snapshot the pre-call state. The matching
    // _runOracle() reads this snapshot back. All the "before" balances are re-read
    // AFTER the rewind inside _runOracle (native balance is storage, so vm.revertToState
    // restores it) — nothing needs to be captured or passed in by the test body.
    function _beginOracle() internal {
        vm.recordLogs();
        _snapId = vm.snapshotState();   // state immediately before the calls
    }

    // Non-reverting ERC20 balanceOf (staticcall): a non-token address or a token
    // that reverts on odd inputs returns 0 instead of aborting the whole test.
    // Gas-capped: a real balanceOf is <5k gas. A non-token whose fallback does real
    // work would otherwise burn the whole budget here (a state change in static
    // context is an exceptional, gas-consuming halt), OOG-ing the oracle.
    function _erc20BalanceOf(address token, address who) internal view returns (uint256) {
        (bool ok, bytes memory ret) = token.staticcall{gas: 100000}(
            abi.encodeWithSelector(0x70a08231, who)   // balanceOf(address)
        );
        return (ok && ret.length >= 32) ? abi.decode(ret, (uint256)) : 0;
    }

    // ── Net-profit valuation (fork DEX + off-fork mock/empty DEX) ───────────────
    // Everything is priced into ONE numéraire: the chain's wrapped-native token
    // (WETH/WBNB/WAVAX/WFTM). Native coin counts 1:1; every other token is valued by
    // a slippage-aware on-chain DEX quote (getAmountsOut over the FULL bag), so a
    // manipulated/illiquid pool prices the bag at its realizable (collapsed) value —
    // no infinite paper profit. The venue (UniV2-compatible router + wrapped + a
    // stable hop) is resolved purely from block.chainid; it is NOT threaded through
    // config. Off-fork (or an unknown fork chain) ⇒ router 0 ⇒ all token quotes 0 ⇒ the
    // value verdicts price native ONLY (the mock/empty DEX): a native net profit still
    // proves the high tier, a token-only profit degrades to the heuristics. Never an
    // over-count.

    // (router, wrapped-native, stable-hop) for the forked chain. VERIFY before edit:
    // wrong wrapped/router only under-counts (quote fails → 0), never an FP.
    // Off-fork = the MOCK/EMPTY DEX: no on-chain router, so `_quoteToNumeraire` returns
    // 0 for every token and `_portfolioValue` prices native 1:1 ONLY. That is what lets
    // the tier=high value verdicts fire inline (a proven native-coin net profit) with no
    // real DEX and no Pareto rule — token-denominated profit stays a tier=heuristic lead.
    function _pricingVenue() internal view returns (address router, address wrapped, address stable) {
        if (!forkMode) return (address(0), address(0), address(0));   // mock/empty DEX
        uint256 id = block.chainid;
        if (id == 1) {            // Ethereum — Uniswap V2
            return (0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D,
                    0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2,   // WETH
                    0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);  // USDC
        } else if (id == 56) {    // BSC — PancakeSwap V2
            return (0x10ED43C718714eb63d5aA57B78B54704E256024E,
                    0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,   // WBNB
                    0x55d398326f99059fF775485246999027B3197955);  // USDT
        } else if (id == 42161) { // Arbitrum — SushiSwap
            return (0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506,
                    0x82aF49447D8a07e3bd95BD0d56f35241523fBab1,   // WETH
                    0xaf88d065e77c8cC2239327C5EDb3A432268e5831);  // USDC
        } else if (id == 43114) { // Avalanche — Trader Joe
            return (0x60aE616a2155Ee3d9A68541Ba4544862310933d4,
                    0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7,   // WAVAX
                    0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E);  // USDC
        } else if (id == 8453) {  // Base — Uniswap V2
            return (0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24,
                    0x4200000000000000000000000000000000000006,   // WETH
                    0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913);  // USDC
        } else if (id == 250) {   // Fantom — SpookySwap
            return (0xF491e7B69E4244ad4002BC14e878a34207E38c29,
                    0x21be370D5312f44cB42ce377BC9b8a0cEF1A4C83,   // WFTM
                    0x04068DA6C83AFCFA0e13ba15A6696662335D5B75);  // USDC
        }
        return (address(0), address(0), address(0));
    }

    // Value `amount` of `token` in the chain numéraire. amount==0 → 0; token==wrapped →
    // 1:1 (no quote). Else slippage-aware getAmountsOut over [token, wrapped], then the
    // [token, stable, wrapped] fallback; any failure → 0 (under-count, never FP).
    function _quoteToNumeraire(address token, uint256 amount) internal view returns (uint256) {
        if (amount == 0) return 0;
        (address router, address wrapped, address stable) = _pricingVenue();
        if (router == address(0)) return 0;
        if (token == wrapped) return amount;                 // 1:1 short-circuit

        address[] memory path2 = new address[](2);
        path2[0] = token; path2[1] = wrapped;
        uint256 out = _amountsOutLast(router, amount, path2);
        if (out > 0) return out;

        if (stable != address(0) && token != stable) {
            address[] memory path3 = new address[](3);
            path3[0] = token; path3[1] = stable; path3[2] = wrapped;
            out = _amountsOutLast(router, amount, path3);
        }
        return out;
    }

    // gas-capped, revert-proof getAmountsOut → last hop amount (0 on any failure).
    // The gas cap mirrors _erc20BalanceOf: a quote against a fixed trusted router can
    // never OOG or abort the whole oracle.
    function _amountsOutLast(address router, uint256 amount, address[] memory path)
        internal view returns (uint256)
    {
        (bool ok, bytes memory ret) = router.staticcall{gas: 200000}(
            abi.encodeWithSelector(0xd06ca61f, amount, path)  // getAmountsOut(uint256,address[])
        );
        if (!ok || ret.length < 64) return 0;
        uint256[] memory amounts = abi.decode(ret, (uint256[]));
        if (amounts.length == 0) return 0;
        return amounts[amounts.length - 1];
    }

    // Net value (in numéraire) of two actors' holdings across every watched token +
    // native coin. Balances are passed in (not read) because the before/after frames
    // live on opposite sides of vm.revertToState — the caller reads each side in the
    // right frame and the quote prices against that frame's (rolled-back-or-not) pool
    // state. b-balances are zero/native 0 when valuing a single actor (the target).
    function _portfolioValue(
        address[] memory toks,
        uint256[] memory bals_a,
        uint256[] memory bals_b,
        uint256 nativeA,
        uint256 nativeB
    ) internal view returns (uint256 total) {
        // Native is a real coin balance (bounded ≪ 2^256). Token bags come from
        // balanceOf on UNTRUSTED tokens and can report absurd values, so every
        // addition is overflow-GUARDED: a token whose bag or running total would
        // overflow is skipped. The oracle must NEVER revert — a checked-arithmetic
        // panic here would suppress ALL signals for the run. Skipping is also exactly
        // correct: a ~2^256 bag makes getAmountsOut overflow internally → quote 0
        // anyway, so a skipped token contributes the same 0 (no FP, no under-count
        // beyond what the quote already gives).
        unchecked {
            total = nativeA + nativeB;
            for (uint256 i = 0; i < toks.length; i++) {
                uint256 bag = bals_a[i] + bals_b[i];
                if (bag < bals_a[i]) continue;                // bag overflow → skip
                uint256 nt = total + _quoteToNumeraire(toks[i], bag);
                if (nt < total) continue;                     // total overflow → skip
                total = nt;
            }
        }
    }

    // Best-effort ERC20 symbol() read — gas-capped and NEVER reverts (mirrors
    // _erc20BalanceOf), so a non-token address or a malformed return degrades to "" (the
    // caller then names the asset "UnknownERC20Token"). Handles both the modern `string` return
    // and the legacy `bytes32` return (e.g. MKR). The string length is read from the low
    // byte of the ABI length word (symbols are short) to avoid a reverting abi.decode on
    // garbage. Raw bytes are copied verbatim — a symbol with a space would truncate in
    // the whitespace-split parser (display-only degradation, never a crash).
    function _erc20Symbol(address token) internal view returns (string memory) {
        (bool ok, bytes memory ret) = token.staticcall{gas: 50000}(
            abi.encodeWithSelector(0x95d89b41)   // symbol()
        );
        if (!ok || ret.length == 0) return "";
        if (ret.length == 32) {                  // legacy bytes32 symbol
            uint256 n = 0;
            while (n < 32 && ret[n] != 0) { n++; }
            bytes memory b = new bytes(n);
            for (uint256 i = 0; i < n; i++) { b[i] = ret[i]; }
            return string(b);
        }
        if (ret.length >= 96) {                  // ABI string: [offset(32)][len(32)][data]
            uint256 len = uint8(ret[63]);        // low byte of the length word
            if (len == 0 || len > 32 || 64 + len > ret.length) return "";
            bytes memory b = new bytes(len);
            for (uint256 i = 0; i < len; i++) { b[i] = ret[64 + i]; }
            return string(b);
        }
        return "";
    }

    // Human-readable currency symbol of the chain's NATIVE coin, by chainid (default ETH
    // for mainnet/arbitrum/base and every inline/unknown chain). Used BOTH to name the
    // asset on native balance-delta heuristics AND as the value verdicts' `target_asset`
    // label: the numéraire is the wrapped-native token (WETH/WBNB/…, 1:1 with the coin),
    // but we display the plain native symbol (ETH/BNB/…) — the wrapped ADDRESS is still
    // what _pricingVenue quotes against.
    function _nativeSymbol() internal view returns (string memory) {
        uint256 id = block.chainid;
        if (id == 56) return "BNB";      // BSC
        if (id == 43114) return "AVAX";  // Avalanche
        if (id == 250) return "FTM";     // Fantom
        return "ETH";                    // mainnet / arbitrum / base / inline / unknown
    }

    // ── BUG_SIGNAL emitters — two machine-parseable shapes, one console.log each ──
    // The "BUG_SIGNAL: " prefix is preserved so the startswith() detector still flips
    // bug_signal_found. Python parses `k=v` pairs generically, so the two shapes share a
    // parser but carry different keys.
    function _emitLine(string memory name, string memory tier, string memory fields) internal view {
        console.log(string.concat("BUG_SIGNAL: ", name, " tier=", tier, fields));
    }

    // Balance-delta HEURISTIC line:
    //   native: BUG_SIGNAL: <name> tier=heuristic asset=<SYM> value=<wei>
    //   ERC20:  BUG_SIGNAL: <name> tier=heuristic asset=<SYM> token_address=<addr> amount=<raw>
    // `asset` is the currency NAME: the native symbol for a native move, else the ERC20's
    // on-chain symbol() ("UnknownERC20Token" when it has none). `token_address` is present
    // ONLY for an ERC20 (omitted for native). The magnitude key encodes the unit: a native
    // move carries `value=` (numéraire wei, 18-dec) while an ERC20 carries `amount=` (raw
    // base-unit balance delta — decimals unknown, so NOT scaled).
    function _emitHeuristic(
        string memory name, string memory assetSym, address tokenAddr, uint256 amount
    ) internal view {
        string memory f = string.concat(" asset=", assetSym);
        if (tokenAddr != address(0)) {
            f = string.concat(f, " token_address=", vm.toString(tokenAddr), " amount=", vm.toString(amount));
        } else {
            f = string.concat(f, " value=", vm.toString(amount));
        }
        _emitLine(name, "heuristic", f);
    }

    // Net-worth VALUE-VERDICT line (tier=high):
    //   BUG_SIGNAL: <name> tier=high total_asset=<count> target_asset=<SYM> value=<wei>
    // `total_asset` = how many holdings were summed into net worth (native + each watched
    // ERC20). `target_asset` = the numéraire symbol the whole bag was converted into.
    // The magnitude is always the native numéraire, so it carries `value=` (net-worth delta
    // end−start, 18-dec wei) rather than `amount=`.
    function _emitValueVerdict(
        string memory name, uint256 totalAsset, string memory targetAsset, uint256 amount
    ) internal view {
        _emitLine(name, "high", string.concat(
            " total_asset=", vm.toString(totalAsset),
            " target_asset=", targetAsset,
            " value=", vm.toString(amount)
        ));
    }

    // Distinct set of ERC20s to measure = every contract that emitted a Transfer
    // during the run, PLUS the target itself. The target is always included because
    // many targets ARE the vulnerable ERC20 and mutate balances via internal
    // accounting WITHOUT emitting Transfer (e.g. an `unstake` that just does
    // `balances[x] += amount`), which log-based discovery alone misses.
    function _watchedTokens(Vm.Log[] memory logs) internal view returns (address[] memory toks) {
        bytes32 sig = keccak256("Transfer(address,address,uint256)");
        address[] memory tmp = new address[](logs.length + 1);
        uint256 n = 0;
        tmp[n++] = target_address;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length != 0 && logs[i].topics[0] == sig) {
                address tok = logs[i].emitter;
                bool seen = false;
                for (uint256 j = 0; j < n; j++) { if (tmp[j] == tok) { seen = true; break; } }
                if (!seen) { tmp[n++] = tok; }
            }
        }
        toks = new address[](n);
        for (uint256 i = 0; i < n; i++) { toks[i] = tmp[i]; }
    }

    // Read every watched token's AFTER balances (attacker / target), post-call. Its
    // own frame keeps _runOracle's local count low (the long call sequence + the
    // oracle must never share a frame → "stack too deep"). These arrays live in
    // MEMORY, which survives vm.revertToState — only storage is rolled back.
    function _afterState(address[] memory toks)
        internal view
        returns (uint256[] memory aAft, uint256[] memory tAft)
    {
        uint256 n = toks.length;
        aAft = new uint256[](n);
        tAft = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            aAft[i] = _erc20BalanceOf(toks[i], attacker_address);
            tAft[i] = _erc20BalanceOf(toks[i], target_address);
        }
    }

    // After the rewind: compare each token's BEFORE state (re-read here, post-rewind)
    // to the captured AFTER memory arrays and emit the ERC20 balance-delta heuristics
    // (tier=heuristic). There is ONE attacker identity now, so reentrancy profit
    // lands as an attacker_gained on attacker_address — no separate bag.
    // The attacker GAIN check scans EVERY watched asset (that's how profit realized in
    // an external token like WETH is caught); the DRAIN check counts only the TARGET's
    // own holdings dropping (an external pair/router/LP legitimately loses balance
    // during a swap — not a loss ON the target). Soundness of the >20%-drain
    // heuristic: the sequence executes AS the attacker, so a balance drop is an
    // attacker-driven drain, never a legit owner withdrawal.
    function _emitErc20Signals(
        address[] memory toks,
        uint256[] memory aAft,
        uint256[] memory tAft
    ) internal view {
        for (uint256 i = 0; i < toks.length; i++) {
            uint256 aBef = _erc20BalanceOf(toks[i], attacker_address);
            uint256 tBef = _erc20BalanceOf(toks[i], target_address);
            bool gained = aAft[i] > aBef;
            bool drained = tBef > 0 && tAft[i] < tBef * 80 / 100;
            // Asset name = the ERC20's symbol(), or "UnknownERC20Token" when it has none.
            // Resolved once, only when a signal will actually fire.
            string memory sym = (gained || drained) ? _erc20Symbol(toks[i]) : "";
            string memory assetSym = bytes(sym).length > 0 ? sym : "UnknownERC20Token";
            if (gained) {
                _emitHeuristic("attacker_gained", assetSym, toks[i], aAft[i] - aBef);
            }
            if (drained) {
                _emitHeuristic("target_drained", assetSym, toks[i], tBef - tAft[i]);
            }
        }
    }

    // The whole post-run oracle, in its own call frame. Takes NO arguments: the actor
    // addresses are harness state (target_address / attacker_address, set in setUp) and
    // the pre-call snapshot id is _snapId (set by _beginOracle). Every "before" quantity
    // — native balances included — is re-read AFTER the rewind, so the test body captures
    // and threads in nothing. Two classes of signal:
    //   • value verdicts (attacker_profit / target_loss, tier=high) — ALL modes, net
    //     numéraire value of ALL holdings end-vs-start; FP-free by construction (net > 0).
    //     On a fork the bag is priced through the on-chain DEX; off-fork the mock/empty
    //     DEX prices native ONLY, so a native-coin net profit still proves the high tier
    //     (token-only profit degrades to the heuristics). The END value is computed BEFORE
    //     the rewind (end holdings × end pool prices — the rewind rolls BOTH back), the
    //     START value AFTER (start holdings × start prices).
    //   • balance-delta heuristics (attacker_gained / target_drained, tier=heuristic) —
    //     all modes. AFTER balances are captured before the rewind (native + ERC20);
    //     BEFORE balances are re-read after the rewind (storage is rolled back, so the
    //     native/token balances are restored to their pre-call values).
    // Memory arrays survive vm.revertToState; only storage (balances, pool reserves) is
    // rolled back — hence the strict frame discipline.
    function _runOracle() internal {
        address[] memory toks = _watchedTokens(vm.getRecordedLogs());
        (uint256[] memory aAft, uint256[] memory tAft) = _afterState(toks);

        // END-state portfolio values (before the rewind, while the pool still reflects
        // the attack). Off-fork the empty DEX makes this the native-only end value.
        (uint256 atkValEnd, uint256 tgtValEnd) = _endPortfolioValues(toks, aAft, tAft);

        // Native AFTER balances — storage, so read BEFORE the rewind.
        uint256 aNativeAft = attacker_address.balance;
        uint256 tNativeAft = target_address.balance;

        vm.revertToState(_snapId);

        // Native BEFORE balances — storage is now rolled back to the pre-call frame, so
        // the pre-run native balances are simply re-read here (mirrors the ERC20/value
        // "before" reads, all taken post-rewind). Emitted in its own frame so _runOracle's
        // stack stays shallow (the long call sequence already crowds it → "stack too deep").
        _emitNativeHeuristics(attacker_address.balance, aNativeAft, target_address.balance, tNativeAft);

        _emitValueVerdicts(toks, atkValEnd, tgtValEnd);
        _emitErc20Signals(toks, aAft, tAft);
    }

    // Native-coin balance-delta heuristics. Balances are passed in (the AFTER values were
    // captured before the rewind, the BEFORE values re-read after it by _runOracle). There
    // is one attacker identity (attacker_address); the target-drain >20% check is sound
    // because the sequence runs AS the attacker.
    function _emitNativeHeuristics(uint256 aNativeBef, uint256 aNativeAft, uint256 tNativeBef, uint256 tNativeAft) internal view {
        string memory nat = _nativeSymbol();
        if (aNativeAft > aNativeBef) { _emitHeuristic("attacker_gained", nat, address(0), aNativeAft - aNativeBef); }
        if (tNativeAft < tNativeBef * 80 / 100) { _emitHeuristic("target_drained", nat, address(0), tNativeBef - tNativeAft); }
    }

    // END-state value of the attacker bag and of the target, in its own frame to keep
    // _runOracle's stack shallow. Called BEFORE the rewind.
    function _endPortfolioValues(
        address[] memory toks,
        uint256[] memory aAft, uint256[] memory tAft
    ) internal view returns (uint256 atkValEnd, uint256 tgtValEnd) {
        uint256[] memory zero = new uint256[](toks.length);
        atkValEnd = _portfolioValue(toks, aAft, zero, attacker_address.balance, 0);
        tgtValEnd = _portfolioValue(toks, tAft, zero, target_address.balance, 0);
    }

    // START-state values (read AFTER the rewind) + the value verdicts. attacker_profit
    // fires when the attacker bag is worth strictly more after; target_loss when the
    // target's holdings are worth strictly less. amount = the net-worth delta in the
    // numéraire; total_asset = how many holdings were summed (native + every watched
    // ERC20); target_asset = the native coin SYMBOL (ETH/BNB/…) — the numéraire is the
    // wrapped-native token (1:1 with the coin) but we label it with the plain coin.
    function _emitValueVerdicts(address[] memory toks, uint256 atkValEnd, uint256 tgtValEnd) internal view {
        (uint256[] memory aBef, uint256[] memory tBef) = _afterState(toks);
        uint256[] memory zero = new uint256[](toks.length);
        uint256 atkValStart = _portfolioValue(toks, aBef, zero, attacker_address.balance, 0);
        uint256 tgtValStart = _portfolioValue(toks, tBef, zero, target_address.balance, 0);
        uint256 count = toks.length + 1;             // watched ERC20s + native
        string memory num = _nativeSymbol();         // native coin symbol (ETH/BNB/…)
        if (atkValEnd > atkValStart) {
            _emitValueVerdict("attacker_profit", count, num, atkValEnd - atkValStart);
        }
        if (tgtValStart > tgtValEnd) {
            _emitValueVerdict("target_loss", count, num, tgtValStart - tgtValEnd);
        }
    }

    // ── FinanceFuzz competitor helpers (used only by finance.sol.tpl) ──────────
    // Differential equivalence oracle: the finance test runs the sequence T and each
    // detector-flavored variant T′ from the same snapshot, emitting a parseable
    // balance "fingerprint" per tag. The Python oracle (baselines/financefuzz) diffs
    // T vs T′. Unused by the fork/inline/legacy modes — kept here to preserve the
    // single-source-Harness invariant.

    // Snapshot an ERC20's balance over a watched account set (all-zero if not a
    // token). Captured right BEFORE a call so the per-call token-supply invariant
    // can compare each changed account's pre vs post balance.
    function _ffBalances(address token, address[] memory accts)
        internal view returns (uint256[] memory bals)
    {
        bals = new uint256[](accts.length);
        if (token == address(0)) return bals;
        for (uint256 i = 0; i < accts.length; i++) {
            bals[i] = _erc20BalanceOf(token, accts[i]);
        }
    }

    // PER-CALL token-supply invariant (port of upstream TokenBalanceDetector, which
    // prepares/runs the detector around each transaction). `preBals` is the watched
    // set's balances captured before THIS call; `logs` is this call's Transfer events
    // (vm.getRecordedLogs() clears the buffer, so each call sees only its own). The
    // changed accounts (non-mint/burn participants) are summed pre vs post: an honest
    // transfer conserves the sum; a self-credit / overflow-mint grows it. Emits one
    // `FF_INV <preSum> <postSum>` line for this call (oracle flags preSum != postSum).
    // A changed account outside the watched set has no captured "before" and is
    // skipped — sound here because every transfer participant (actors +
    // ADDRESS_ARG_POOL recipients) is in the watched set.
    function _ffInvEmit(
        address token, address[] memory accts, uint256[] memory preBals, Vm.Log[] memory logs
    ) internal view {
        if (token == address(0)) return;
        address[] memory changed = _ffChangedAccounts(logs, token);
        if (changed.length == 0) return;
        uint256 preSum;
        uint256 postSum;
        for (uint256 i = 0; i < changed.length; i++) {
            for (uint256 j = 0; j < accts.length; j++) {
                if (accts[j] == changed[i]) {
                    preSum += preBals[j];
                    postSum += _erc20BalanceOf(token, changed[i]);
                    break;
                }
            }
        }
        console.log(string.concat(
            "FF_INV ", vm.toString(preSum), " ", vm.toString(postSum)
        ));
    }

    // Accounts whose balance changed via a NON-mint/non-burn Transfer emitted by
    // `token` during the run (port of TokenBalanceDetector: from/to both non-zero).
    // Backs the token-supply invariant — summing balanceOf over exactly these
    // accounts is constant for an honest transfer but grows for TransferMint /
    // overflow-mint. Excluding mint/burn (zero address) is what stops a legitimate
    // mint from registering as a false invariant violation.
    function _ffChangedAccounts(Vm.Log[] memory logs, address token)
        internal pure returns (address[] memory accts)
    {
        bytes32 sig = keccak256("Transfer(address,address,uint256)");
        address[] memory tmp = new address[](logs.length * 2);
        uint256 n = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (token == address(0) || logs[i].emitter != token) continue;
            if (logs[i].topics.length < 3 || logs[i].topics[0] != sig) continue;
            address from = address(uint160(uint256(logs[i].topics[1])));
            address to = address(uint160(uint256(logs[i].topics[2])));
            if (from == address(0) || to == address(0)) continue;   // skip mint/burn
            n = _ffPush(tmp, n, from);
            n = _ffPush(tmp, n, to);
        }
        accts = new address[](n);
        for (uint256 i = 0; i < n; i++) accts[i] = tmp[i];
    }

    function _ffPush(address[] memory arr, uint256 n, address a) private pure returns (uint256) {
        for (uint256 j = 0; j < n; j++) { if (arr[j] == a) return n; }
        arr[n] = a;
        return n + 1;
    }

    // Emit the per-account ETH (+ optional token) balances for one tag T/T′. Parsed
    // by oracle.parse_fingerprints. One pre-formatted string per console.log so a
    // single forge-std overload always matches.
    function _ffEmit(string memory tag, address token, address[] memory accts) internal view {
        for (uint256 i = 0; i < accts.length; i++) {
            console.log(string.concat(
                "FF_FP ", tag, " ", vm.toString(i), " ", vm.toString(accts[i].balance)
            ));
            if (token != address(0)) {
                console.log(string.concat(
                    "FF_FP_TOK ", tag, " ", vm.toString(i), " ",
                    vm.toString(_erc20BalanceOf(token, accts[i]))
                ));
            }
        }
    }
}

// Recipient that rejects incoming Ether — etched onto a caller address for the
// FinanceFuzz "gasless send" variant. A target that checks its send's return value
// reverts (the call is logged as a failure → the oracle's fail-set gate skips it);
// a target that ignores the return proceeds, leaving its accounting inconsistent
// with the (un-credited) recipient — the unchecked-send equivalence violation.
contract FFRejectEther {
    receive() external payable { revert("FFRejectEther"); }
    fallback() external payable { revert("FFRejectEther"); }
}
