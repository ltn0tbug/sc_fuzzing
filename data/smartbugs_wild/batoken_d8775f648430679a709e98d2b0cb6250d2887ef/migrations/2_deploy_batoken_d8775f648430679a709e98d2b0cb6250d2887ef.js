const BAToken = artifacts.require("BAToken");

module.exports = async function (deployer, network, accounts) {
  // Deployment Parameters
  const ethFundDeposit = accounts[0];         // ETH collected goes here
  const batFundDeposit = accounts[2];         // Initial BAT allocation (500M) for Brave Intl
  const fundingStartBlock = 100;              // Example block number
  const fundingEndBlock = fundingStartBlock + 100000; // Example duration

  await deployer.deploy(BAToken, ethFundDeposit, batFundDeposit, fundingStartBlock, fundingEndBlock);
};
