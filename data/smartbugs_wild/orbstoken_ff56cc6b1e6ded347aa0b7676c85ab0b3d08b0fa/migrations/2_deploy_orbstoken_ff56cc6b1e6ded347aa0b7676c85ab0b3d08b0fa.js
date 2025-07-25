const OrbsToken = artifacts.require("OrbsToken");

module.exports = async function (deployer, network, accounts) {
  const distributor = accounts[0]; // Change if needed (e.g., to a multisig wallet or your own address)

  await deployer.deploy(OrbsToken, distributor);
};
