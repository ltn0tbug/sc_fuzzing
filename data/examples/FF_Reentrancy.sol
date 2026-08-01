// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FF_Reentrancy — FinanceFuzz reentrancy fixture.
/// @notice `claim()` sends 1 ether and only THEN records the claim, so a re-entrant
///         caller can drain multiple rewards in one transaction. FinanceFuzz's
///         reentrancy detector compares the re-entrant execution against the
///         non-re-entrant one; the attacker's balance differs → equivalence violated.
///
/// Forge adaptation: the executor arms the unified Attacker (attacker_address)
/// to re-enter `claim()` for the T′ variant (vs T which does not re-enter). The
/// contract is funded by the harness (vm.deal).
contract FF_Reentrancy {
    mapping(address => bool) public claimed;

    /// BUG: external call before the state update (claimed set after the send).
    function claim() external {
        require(!claimed[msg.sender], "already claimed");
        (bool ok, ) = msg.sender.call{value: 1 ether}("");
        require(ok, "transfer failed");
        claimed[msg.sender] = true;   // too late — re-entry already drained more
    }

    receive() external payable {}
}
