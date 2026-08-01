// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/${contract_name}.sol";
// Shared harness — provides the ERC20 balance helpers, the FinanceFuzz fingerprint
// emitters (_ffEmit / _ffInvEmit) and FFRejectEther. Written next to this test by the
// FinanceFuzz executor so the relative import resolves.
import "./Harness.sol";

// FinanceFuzz competitor harness. Unlike the other modes it runs the sequence T and
// each detector-flavored variant T′ from one snapshot (vm.snapshotState /
// vm.revertToState), emitting a balance "fingerprint" per block. The Python oracle
// (baselines/financefuzz/oracle.py) diffs T vs T′ to flag equivalence violations and
// reads FF_INV for the token-supply invariant. Modern (>=0.8) deploy path only.
contract FuzzInputTest is SCFuzzHarness {
    ${contract_name} target;
    address[] _ffAccts;

    function setUp() public {
        deployer_address = makeAddr("deployer");
        attacker_address = makeAddr("attacker");
        vm.deal(deployer_address, ${initial_balance} ether);

        ${dep_deploys}

        vm.prank(deployer_address);
        target = new ${contract_name}${ctor_value}(${ctor_args});
        target_address = address(target);

        ${dep_setup_calls}

        // Unified attacker contract (the single attacker identity at attacker_address).
        vm.prank(attacker_address);
        attacker = new Attacker(target_address);
        attacker_address = address(attacker);

        vm.deal(attacker_address, ${initial_balance} ether);
        vm.deal(deployer_address, ${initial_balance} ether);
        vm.deal(target_address, ${initial_balance} ether);

        // Watched-account set for the fingerprint = actors + the address-argument pool
        // (transfer recipients are drawn from it, so honest transfers stay within the
        // watched set and the supply invariant holds).
        ${ff_accounts_init}
    }

    function test_fuzz_input() public {
        vm.recordLogs();
        uint256 _s0 = vm.snapshotState();

        ${blocks}
    }
}
