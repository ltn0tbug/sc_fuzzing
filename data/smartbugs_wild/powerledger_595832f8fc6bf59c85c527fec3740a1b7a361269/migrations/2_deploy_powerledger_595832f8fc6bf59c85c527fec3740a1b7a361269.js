const PowerLedger = artifacts.require("PowerLedger");

module.exports = async function (deployer, network, accounts) {
  // The migrationInfoSetter address — set to the deployer for simplicity
  const migrationInfoSetter = accounts[0];

  await deployer.deploy(PowerLedger, migrationInfoSetter);
};
