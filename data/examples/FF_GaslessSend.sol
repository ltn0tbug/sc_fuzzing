// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FF_GaslessSend — FinanceFuzz unchecked / gasless-send fixture.
/// @notice `payout()` sends Ether with a low-level call but ignores the return
///         value. If the recipient cannot accept the Ether, the send silently fails
///         while the contract proceeds as though it succeeded. FinanceFuzz's gasless
///         detector flags the inconsistency.
///
/// Forge adaptation: the executor etches a reverting recipient (FFRejectEther) onto
/// the caller address for the T′ variant. The send then fails; because the return
/// value is unchecked the call does NOT revert (same success status as T → the
/// detector's success gate passes) yet the recipient balance differs → flagged. A
/// checked version would revert under T′ (different success status → gated out).
contract FF_GaslessSend {
    /// BUG: return value of the value-bearing call is ignored (unchecked send).
    function payout() external {
        msg.sender.call{value: 1 ether}("");   // solhint-disable-line — intentionally unchecked
    }

    receive() external payable {}
}
