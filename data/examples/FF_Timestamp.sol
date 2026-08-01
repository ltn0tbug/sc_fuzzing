// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FF_Timestamp — FinanceFuzz timestamp-dependency fixture.
/// @notice `spin()` pays the caller only when `block.timestamp` is past a threshold.
///         FinanceFuzz's timestamp detector re-runs the sequence under a randomized
///         timestamp (here via vm.warp); because the payout flips, the final balances
///         differ and the equivalence property is violated.
///
/// Reachable: any `spin()` call. The forge harness runs T at the default block
/// timestamp (1, below the threshold → no payout) and the T′ variant after warping
/// to a large random time (above the threshold → payout).
contract FF_Timestamp {
    /// BUG: payout gated on the (miner-influenceable) block timestamp.
    function spin() external {
        if (block.timestamp > 100) {
            (bool ok, ) = payable(msg.sender).call{value: 1 ether}("");
            require(ok, "transfer failed");
        }
    }

    receive() external payable {}
}
