// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "./Harness.sol";

// FinanceFuzz competitor harness — on-chain (fork) target. The target already exists
// on-chain at ${target_address}; we fork the chain and call it through its verified
// ABI. The test body is identical to finance.sol.tpl: run T and each detector
// variant T′ from one snapshot, emit a fingerprint per block. Note: only the
// timestamp/TOD/invariant detectors are generally meaningful on a live fork; the
// reentrancy/gasless approximations still execute but may simply show no difference.
${interface_decl}

// Declared non-target contracts/tokens the fuzz body may call (extend.external).
${external_interfaces}
${external_consts}

contract FuzzInputTest is SCFuzzHarness {
    I${contract_name} target = I${contract_name}(${target_address});
    address[] _ffAccts;

    function setUp() public {
        vm.createSelectFork("${chain}", ${fork_block});

        // Fork mode has no deployer — the target is already deployed on-chain.
        attacker_address = makeAddr("attacker");
        target_address   = ${target_address};

        // Unified attacker contract (the single attacker identity at attacker_address).
        vm.prank(attacker_address);
        attacker = new Attacker(target_address);
        attacker_address = address(attacker);

        vm.deal(attacker_address, ${initial_balance} ether);

        ${ff_accounts_init}
    }

    function test_fuzz_input() public {
        vm.recordLogs();
        uint256 _s0 = vm.snapshotState();

        ${blocks}
    }
}
