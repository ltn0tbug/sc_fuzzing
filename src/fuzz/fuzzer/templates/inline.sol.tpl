// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/${contract_name}.sol";
// Callback-capable attacker + financial-loss oracle (shared by all three modes).
// Written next to this test by FoundryFuzzer so the relative import resolves.
import "./Harness.sol";

contract FuzzInputTest is SCFuzzHarness {
    ${contract_name} target;

    function setUp() public {
        deployer_address = makeAddr("deployer");
        attacker_address = makeAddr("attacker");

        // Fund the deployer before deploy so a payable constructor (${ctor_value})
        // can receive value. Re-dealt below to the same balance (vm.deal is absolute).
        vm.deal(deployer_address, ${initial_balance} ether);

        // Deploy co-located dependency contracts (same source file) BEFORE the
        // target, binding each to `_depaddr_<alias>` for constructor_args to
        // reference. Empty unless extend.pre_deploy is set.
        ${dep_deploys}

        vm.prank(deployer_address);
        target = new ${contract_name}${ctor_value}(${ctor_args});
        target_address = address(target);

        // Post-deploy wiring (e.g. setLog(address(dep))) via the target's own
        // public API. Empty unless extend.setup_calls is set.
        ${dep_setup_calls}

        // Unified attacker contract (the single attacker identity at attacker_address).
        vm.prank(attacker_address);
        attacker = new Attacker(target_address);
        attacker_address = address(attacker);

        vm.deal(attacker_address, ${initial_balance} ether);
        vm.deal(deployer_address, ${initial_balance} ether);
        vm.deal(target_address, ${initial_balance} ether);
    }

    function test_fuzz_input() public {
        // _beginOracle() records logs (for post-run token discovery) + snapshots the
        // pre-call state; _runOracle() re-reads every "before" balance after rewinding to
        // that snapshot, so nothing is captured or threaded through here.
        _beginOracle();

        ${calls_code}

        // Token discovery, before/after compare and signal emission all run in _runOracle
        // (Harness.sol) so test_fuzz_input stays small (the long call sequence and the
        // oracle never share a stack frame).
        _runOracle();
    }
}
