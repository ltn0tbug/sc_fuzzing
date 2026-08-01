// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FF_TOD — FinanceFuzz transaction-order-dependency fixture.
/// @notice A one-shot reward paid to whoever calls `claim()` first. The final
///         balances depend on the order of the (same-set) transactions: if two
///         different senders both call claim, only the first is paid. FinanceFuzz's
///         TOD detector reorders the sequence by sender and finds the equivalence
///         (final balances) violated.
///
/// Reachable: an individual with `claim()` called by two distinct senders
/// (attacker_address + a second pooled sender from the FinanceFuzz watched set).
/// The contract is funded by the harness (vm.deal) after deployment.
contract FF_TOD {
    bool public paid;
    uint256 public constant REWARD = 1 ether;

    /// First caller wins the reward — order-dependent outcome. `claim` is the only
    /// state-changing function, so a multi-call individual is a sequence of claims by
    /// (randomly) different senders; reordering by sender changes who is paid.
    function claim() external {
        require(!paid, "already paid");
        paid = true;
        (bool ok, ) = payable(msg.sender).call{value: REWARD}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
