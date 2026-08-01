// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FF_Benign — FinanceFuzz negative control (no property should be violated).
/// @notice A correct ERC20: `faucet()` mints to the caller (a Transfer from the zero
///         address — excluded from the supply invariant), and `transfer` moves value
///         with a proper balance check so the sum over changed accounts is conserved.
///         There is no Ether flow, timestamp/order dependence, reentrancy, or
///         unchecked send — so FinanceFuzz should report ZERO violations here,
///         exercising the paper's "no false positives" claim.
contract FF_Benign {
    string public name = "FFBenign";
    string public symbol = "FFB";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /// Mint to the caller (legitimate supply growth — a mint Transfer is excluded
    /// from the changed-account invariant, so this is not a violation).
    function faucet(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
        emit Transfer(address(0), msg.sender, amount);
    }

    /// Correct transfer: checked, value-conserving (sum over {from,to} unchanged).
    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "insufficient");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
}
