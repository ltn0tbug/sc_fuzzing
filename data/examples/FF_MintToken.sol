// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FF_MintToken — FinanceFuzz per-call invariant negative control.
/// @notice A CORRECT mintable ERC20: `mint(amount)` legitimately creates supply and
///         emits a from==0 Transfer (a mint, EXCLUDED from the token-supply invariant);
///         `transfer` is value-conserving. The sequence `mint(100); transfer(30, …)`
///         must report NO invariant violation.
///
///         This is the regression fixture for the per-call invariant fix: the old
///         whole-sequence bracket took its "before" snapshot at pre-T (before the
///         mint), so the mint leaked into the changed-account diff → a FALSE positive.
///         Upstream (TokenBalanceDetector) checks per transaction, so the mint is
///         already in the transfer tx's "before" state and never enters the diff.
contract FF_MintToken {
    string public name = "FFMintToken";
    string public symbol = "FFMT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    /// Legitimate mint: supply grows, emitted as a from==0 Transfer (excluded from the
    /// changed-account invariant — minting is allowed to create value).
    function mint(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
        emit Transfer(address(0), msg.sender, amount);
    }

    /// Correct, value-conserving transfer: sum over {from, to} is unchanged.
    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "insufficient");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
}
