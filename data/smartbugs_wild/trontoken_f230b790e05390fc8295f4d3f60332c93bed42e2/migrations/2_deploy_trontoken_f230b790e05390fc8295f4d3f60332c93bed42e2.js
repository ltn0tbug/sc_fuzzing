const TronToken = artifacts.require("TronToken");

module.exports = async function (deployer, network, accounts) {
  // Choose the founder's address — first account by default
  const founderAddress = accounts[0];

  await deployer.deploy(TronToken, founderAddress);
};
