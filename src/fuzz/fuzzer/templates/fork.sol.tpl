// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
// Callback-capable attacker + financial-loss oracle (shared by all three modes).
// Written next to this test by FoundryFuzzer so the relative import resolves.
import "./Harness.sol";

// Auto-generated from the on-chain target's verified ABI.
${interface_decl}

// Declared non-target contracts/tokens the fuzz body may call (from the dataset
// row's `extend.external`). Empty in target-only mode. Each is a minimal
// interface + a file-level address constant bound to its on-chain address.
${external_interfaces}
${external_consts}

contract FuzzInputTest is SCFuzzHarness {
    I${contract_name} target = I${contract_name}(${target_address});

    function setUp() public {
        vm.createSelectFork("${chain}", ${fork_block});

        // Price the value verdicts (attacker_profit / target_loss) through the REAL
        // on-chain DEX: we are on a fork, so a router exists to value every holding into
        // the chain numéraire. inline/legacy leave forkMode false → the mock/empty DEX
        // (native-only pricing); the verdicts themselves fire in every mode.
        forkMode = true;

        // Fork mode has no deployer: the target already exists on-chain and only the
        // attacker acts. deployer_address is intentionally unset. target_address comes
        // from the fork.
        attacker_address = makeAddr("attacker");
        target_address   = ${target_address};

        // Unified attacker contract (the single attacker identity at attacker_address).
        vm.prank(attacker_address);
        attacker = new Attacker(target_address);
        attacker_address = address(attacker);

        vm.deal(attacker_address, ${initial_balance} ether);
    }

    function test_fuzz_input() public {
        // Financial-loss oracle: measure attacker/target balances before vs after the
        // run across the native coin AND every ERC20 that moved. The sequence runs ONCE.
        // _beginOracle() starts log recording (for post-run token discovery) and snapshots
        // the pre-call state; _runOracle() re-reads every "before" balance after rewinding
        // to that snapshot, so nothing is captured or threaded through here. We are NOT
        // FinanceFuzz — there is no differential T→T′ re-execution.
        _beginOracle();

        ${calls_code}

        // Token discovery, before/after compare and signal emission all run in _runOracle
        // (Harness.sol) so test_fuzz_input stays small — the long call sequence and the
        // oracle never share a stack frame.
        _runOracle();
    }
}
