const SKYFToken = artifacts.require("SKYFToken");

module.exports = async function (deployer, network, accounts) {
  // Assign addresses from available accounts (customize as needed)
  const crowdsaleWallet = accounts[0];
  const networkDevelopmentWallet = accounts[2];
  const communityDevelopmentWallet = accounts[3];
  const reserveWallet = accounts[4];
  const bountyWallet = accounts[5];
  const teamWallet = accounts[6];
  const siteAccount = accounts[7];

  await deployer.deploy(
    SKYFToken,
    crowdsaleWallet,
    networkDevelopmentWallet,
    communityDevelopmentWallet,
    reserveWallet,
    bountyWallet,
    teamWallet,
    siteAccount
  );
};
