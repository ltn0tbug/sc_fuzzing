// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerablePool
/// @notice Deliberately vulnerable DeFi staking/rewards pool — Solidity 0.8.0+.
///         Designed so every fuzzing strategy can find a real, exploitable bug.
///
///  Bug map:
///   reentrancy_probe    → claimRewards(): ETH sent before pendingRewards zeroed.
///                         No unchecked needed: state write is assignment-to-zero,
///                         not a subtraction, so no arithmetic underflow occurs.
///   overflow_probe      → computeReward() and deposit() accrual: staked * rewardRate
///                         overflows uint256 for large rewardRate values.
///   access_control_probe→ setRewardRate / setMinDeposit / emergencyWithdraw:
///                         all missing onlyOwner.
///   flash_loan_probe    → sharePrice() reads address(this).balance — anyone who
///                         sends ETH directly inflates the price and dilutes new
///                         depositors. Combined with unprotected setRewardRate this
///                         enables same-tx oracle manipulation without a real loan.
///   state_manipulation  → setRewardRate(huge) → deposit(X) → deposit(tiny) →
///                         claimRewards(): three-step cross-function state corruption
///                         that inflates rewards far beyond deposited principal.
///   boundary_values     → earlyWithdrawFee() has cliffs at 0.1 / 10 / 100 ether;
///                         setMinDeposit(0) unlocks zero-value deposit edge cases.
///   random_sequence     → broad coverage across all public functions.
contract VulnerablePool {
    address public owner;
    uint256 public rewardRate;   // reward wei minted per staked wei per deposit-trigger
    uint256 public totalStaked;
    uint256 public totalShares;
    bool    public paused;
    uint256 public minDeposit;

    struct Account {
        uint256 staked;
        uint256 shares;
        uint256 pendingRewards;
    }

    mapping(address => Account) public accounts;

    event Deposited(address indexed user, uint256 amount, uint256 shares);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 amount);
    event RewardRateChanged(uint256 oldRate, uint256 newRate);

    constructor() {
        owner      = msg.sender;
        rewardRate = 1e14;        // 0.01% per deposit-trigger — easily overridden
        minDeposit = 0.01 ether;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // ── Deposit / Stake ───────────────────────────────────────────────────────

    /// @notice Deposit ETH. Each deposit also accrues rewards on the EXISTING stake
    ///         before the new amount is added, creating a reward-trigger pattern.
    function deposit() external payable {
        require(!paused, "paused");
        require(msg.value >= minDeposit, "below minimum");

        // Accrue rewards proportional to current stake at the current rewardRate.
        // BUG (overflow): staked * rewardRate overflows uint256 when rewardRate
        // is set to a very large value via the unprotected setRewardRate().
        if (accounts[msg.sender].staked > 0) {
            accounts[msg.sender].pendingRewards +=
                accounts[msg.sender].staked * rewardRate / 1e18;
        }

        // Share issuance: shares = deposit * totalShares / totalStaked.
        // BUG (flash loan): sharePrice = address(this).balance / totalShares.
        // Sending ETH directly inflates the denominator, so a new depositor
        // receives fewer shares than fair value — existing holders are enriched.
        uint256 newShares;
        if (totalShares == 0 || totalStaked == 0) {
            newShares = msg.value;
        } else {
            newShares = msg.value * totalShares / totalStaked;
        }

        accounts[msg.sender].staked  += msg.value;
        accounts[msg.sender].shares  += newShares;
        totalStaked                  += msg.value;
        totalShares                  += newShares;

        emit Deposited(msg.sender, msg.value, newShares);
    }

    /// @notice Withdraw staked ETH (principal only). State updated before ETH send (CEI correct).
    function withdraw(uint256 amount) external {
        require(!paused, "paused");
        require(accounts[msg.sender].staked >= amount, "insufficient stake");

        uint256 sharesToBurn = (accounts[msg.sender].staked == 0) ? 0
            : amount * accounts[msg.sender].shares / accounts[msg.sender].staked;

        accounts[msg.sender].staked -= amount;
        accounts[msg.sender].shares  = accounts[msg.sender].shares >= sharesToBurn
            ? accounts[msg.sender].shares - sharesToBurn : 0;
        totalStaked -= amount;
        if (totalShares >= sharesToBurn) totalShares -= sharesToBurn;

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    // ── Rewards ───────────────────────────────────────────────────────────────

    /// @notice Claim accumulated staking rewards.
    ///
    /// BUG (reentrancy): ETH is sent to msg.sender BEFORE pendingRewards is zeroed.
    /// An attacker contract whose receive() calls claimRewards() again will see the
    /// original pendingRewards on every re-entry and drain the pool.
    ///
    /// Why no unchecked needed: the fix is `pendingRewards = 0` (assignment), not
    /// `pendingRewards -= rewards` (subtraction). Re-entrant calls simply set 0
    /// multiple times on unwind — no arithmetic underflow, no Solidity 0.8 guard fire.
    function claimRewards() external {
        require(!paused, "paused");
        uint256 rewards = accounts[msg.sender].pendingRewards;
        require(rewards > 0, "nothing to claim");

        // BUG: external call before state update — violates CEI
        (bool ok,) = msg.sender.call{value: rewards}("");
        require(ok, "transfer failed");

        accounts[msg.sender].pendingRewards = 0;   // too late — re-entry already ran
        emit RewardsClaimed(msg.sender, rewards);
    }

    // ── Admin (deliberately unprotected — access control bugs) ───────────────

    /// BUG: missing onlyOwner — any attacker can set an arbitrarily large reward rate,
    /// then trigger accrual via a second deposit() to mint unlimited rewards.
    function setRewardRate(uint256 newRate) external {
        emit RewardRateChanged(rewardRate, newRate);
        rewardRate = newRate;
    }

    /// BUG: missing onlyOwner — anyone can lower minDeposit to 0,
    /// enabling zero-value deposits and bypassing deposit guards.
    function setMinDeposit(uint256 newMin) external {
        minDeposit = newMin;
    }

    /// BUG: missing onlyOwner — any caller can drain the contract when paused.
    function emergencyWithdraw() external {
        require(paused, "not paused");
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok, "emergency transfer failed");
    }

    // ── Admin (correctly protected) ───────────────────────────────────────────

    function pause()   external onlyOwner { paused = true; }
    function unpause() external onlyOwner { paused = false; }

    /// BUG: no newOwner != address(0) guard — owner can permanently brick admin.
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    // ── Pure helpers ──────────────────────────────────────────────────────────

    /// BUG (overflow): staked * rate overflows uint256 for large inputs.
    /// Detectable by fuzzer as panic 0x11 (arithmetic overflow).
    function computeReward(uint256 staked, uint256 rate) external pure returns (uint256) {
        return staked * rate / 1e18;
    }

    /// BUG (boundary): amounts in [0, 0.1 ether) pay zero fee — a cliff that
    /// is inconsistent with minDeposit and exploitable after setMinDeposit(0).
    function earlyWithdrawFee(uint256 amount) external pure returns (uint256) {
        if (amount >= 100 ether) return amount * 3 / 100;
        if (amount >=  10 ether) return amount * 2 / 100;
        if (amount >= 0.1 ether) return amount     / 100;
        return 0;
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    /// BUG (flash loan): price is manipulable by direct ETH sends via receive().
    function sharePrice() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return address(this).balance * 1e18 / totalShares;
    }

    function getStake(address user)          external view returns (uint256) { return accounts[user].staked; }
    function getPendingRewards(address user)  external view returns (uint256) { return accounts[user].pendingRewards; }
    function contractBalance()               external view returns (uint256) { return address(this).balance; }

    receive() external payable {}
}
