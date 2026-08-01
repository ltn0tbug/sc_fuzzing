// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FF_TransferMint — FinanceFuzz invariant (token-supply) fixture.
/// @notice `reward(amount)` credits the caller without debiting anyone — value
///         created from nothing, surfaced as a `from == to` (self) Transfer, the
///         TransferMint signature. FinanceFuzz's token-supply invariant (sum of
///         balances over the Transfer-changed accounts) is violated: the changed set
///         is {caller}, and its balance after > before with no offsetting debit.
///         A normal `transfer` (below) is value-conserving and does NOT violate it.
///
/// Reachable by the generator: `reward(value)` called by attacker_address with any
/// non-zero uint256 (the boundary seeds supply large values). No starting balance
/// needed.
contract FF_TransferMint {
    string public name = "FFMint";
    string public symbol = "FFM";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1_000_000 ether;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    /// BUG: credits the caller with no corresponding debit. Emits a from==to Transfer
    /// (both non-zero), so the changed-account balance sum grows → invariant violated.
    function reward(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        emit Transfer(msg.sender, msg.sender, amount);
    }

    /// Correct, value-conserving transfer (no invariant violation on its own).
    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "insufficient");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
}
