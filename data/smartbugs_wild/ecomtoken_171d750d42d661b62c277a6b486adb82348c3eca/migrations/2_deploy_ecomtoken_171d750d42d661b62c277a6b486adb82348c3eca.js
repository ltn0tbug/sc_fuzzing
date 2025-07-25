const EcomToken = artifacts.require("EcomToken");

module.exports = async function (deployer, network, accounts) {
  // You can modify these addresses based on your deployment environment
  const omniTeamAddress = accounts[2];       // example: 0x123...
  const foundationAddress = accounts[3];     // example: 0xabc...

  await deployer.deploy(EcomToken, omniTeamAddress, foundationAddress);
};
