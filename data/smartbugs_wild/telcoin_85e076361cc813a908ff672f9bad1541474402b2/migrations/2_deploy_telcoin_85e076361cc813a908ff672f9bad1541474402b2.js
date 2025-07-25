const Telcoin = artifacts.require("Telcoin");

module.exports = async function (deployer, network, accounts) {
  // The distributor account will receive the full token supply
  const distributor = accounts[0];

  await deployer.deploy(Telcoin, distributor);
};
