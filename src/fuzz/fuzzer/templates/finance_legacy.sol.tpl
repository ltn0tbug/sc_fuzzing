// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "./Harness.sol";

// FinanceFuzz competitor harness — legacy (<0.8) target. The contract source has a
// pre-0.8 pragma so it cannot be imported into this >=0.8 test unit; instead it is
// deployed at runtime via vm.getCode + assembly create and called through this
// auto-generated interface. The test body is identical to finance.sol.tpl: run T
// and each detector-flavored variant T′ from one snapshot, emit a fingerprint per
// block for the Python oracle to diff.
${interface_decl}

contract FuzzInputTest is SCFuzzHarness {
    I${contract_name} target;
    address[] _ffAccts;

    function setUp() public {
        deployer_address = makeAddr("deployer");
        attacker_address = makeAddr("attacker");
        vm.deal(deployer_address, ${initial_balance} ether);

        ${dep_deploys}

        bytes memory _bc = vm.getCode("${contract_name}.sol:${contract_name}");
        ${ctor_args_concat}
        address _addr;
        vm.prank(deployer_address);
        assembly { _addr := create(${ctor_value_create}, add(_bc, 0x20), mload(_bc)) }
        require(_addr != address(0), "deploy failed (constructor reverted?)");
        vm.label(_addr, "${contract_name}");
        target = I${contract_name}(_addr);
        target_address = _addr;

        ${dep_setup_calls}

        // Unified attacker contract (the single attacker identity at attacker_address).
        vm.prank(attacker_address);
        attacker = new Attacker(target_address);
        attacker_address = address(attacker);

        vm.deal(attacker_address, ${initial_balance} ether);
        vm.deal(deployer_address, ${initial_balance} ether);
        vm.deal(target_address, ${initial_balance} ether);

        ${ff_accounts_init}
    }

    function test_fuzz_input() public {
        vm.recordLogs();
        uint256 _s0 = vm.snapshotState();

        ${blocks}
    }
}
