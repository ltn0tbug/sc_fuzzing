const ENJToken = artifacts.require("ENJToken");

module.exports = async function (deployer, network, accounts) {
  // Set deployment parameters
  const crowdFundAddress = accounts[2];
  const advisorAddress = accounts[3];
  const incentivisationFundAddress = accounts[4];
  const enjinTeamAddress = accounts[5];

  await deployer.deploy(
    ENJToken,
    crowdFundAddress,
    advisorAddress,
    incentivisationFundAddress,
    enjinTeamAddress
  );
};
