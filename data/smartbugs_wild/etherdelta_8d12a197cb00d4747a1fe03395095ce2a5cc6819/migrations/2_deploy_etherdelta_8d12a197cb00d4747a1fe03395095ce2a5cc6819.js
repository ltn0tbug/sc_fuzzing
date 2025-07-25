const ReserveToken = artifacts.require("ReserveToken");
const AccountLevelsTest = artifacts.require("AccountLevelsTest");
const EtherDelta = artifacts.require("EtherDelta");

module.exports = async function (deployer, network, accounts) {
  const admin = accounts[0];
  const feeAccount = accounts[2];

  // Fee values: these are example values (0.3%, 0.3%, 0.2%)
  const feeMake = web3.utils.toWei("0.003", "ether");    // 0.3%
  const feeTake = web3.utils.toWei("0.003", "ether");    // 0.3%
  const feeRebate = web3.utils.toWei("0.002", "ether");  // 0.2%

  // Deploy AccountLevelsTest (mock for testing)
  await deployer.deploy(AccountLevelsTest);
  const accountLevelsInstance = await AccountLevelsTest.deployed();

  // Deploy EtherDelta with the mock AccountLevels contract
  await deployer.deploy(
    EtherDelta,
    admin,
    feeAccount,
    accountLevelsInstance.address,
    feeMake,
    feeTake,
    feeRebate
  );

  // Optionally deploy ReserveToken for testing
  await deployer.deploy(ReserveToken);
};
