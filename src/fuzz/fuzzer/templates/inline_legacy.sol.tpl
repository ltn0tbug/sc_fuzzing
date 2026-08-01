// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
// Callback-capable attacker + financial-loss oracle (shared by all three modes).
// Written next to this test by FoundryFuzzer so the relative import resolves.
import "./Harness.sol";

// Auto-generated interface — derived from the contract's ABI. We do NOT import
// the contract source because its pragma is <0.8 and would not compile in this
// test unit. The contract is deployed at runtime via vm.getCode + assembly
// create; this interface provides a typed handle for calls.
${interface_decl}

contract FuzzInputTest is SCFuzzHarness {
    I${contract_name} target;

    function setUp() public {
        deployer_address = makeAddr("deployer");
        attacker_address = makeAddr("attacker");

        // Fund the deployer before deploy so a payable constructor can receive
        // the create() value. Re-dealt below to the same balance (vm.deal is absolute).
        vm.deal(deployer_address, ${initial_balance} ether);

        // Deploy co-located dependency contracts (defined in the same source file)
        // BEFORE the target, binding each to `_depaddr_<alias>` so the target's
        // constructor args can reference it. Empty unless extend.pre_deploy is set.
        ${dep_deploys}

        // Deploy the legacy-pragma contract via runtime bytecode. The artifact
        // is compiled separately by forge (auto_detect_solc=true picks solc <0.8).
        bytes memory _bc = vm.getCode("${contract_name}.sol:${contract_name}");
        ${ctor_args_concat}
        address _addr;
        vm.prank(deployer_address);
        assembly { _addr := create(${ctor_value_create}, add(_bc, 0x20), mload(_bc)) }
        require(_addr != address(0), "deploy failed (constructor reverted?)");
        // Label the deployed address so forge's debug dump can identify it by
        // contract name. Required by our coverage parser (see fuzzer/coverage.py).
        vm.label(_addr, "${contract_name}");
        target = I${contract_name}(_addr);
        target_address = _addr;

        // Post-deploy wiring (e.g. SetLogFile(address(dep))) via the target's own
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
        // (Harness.sol) so test_fuzz_input stays small (no shared frame with the calls).
        _runOracle();
    }
}
