const Trustcoin = artifacts.require("Trustcoin");

module.exports = async function (deployer, network, accounts) {
  const migrationInfoSetter = accounts[0]; // Replace with secure multisig address if needed

  await deployer.deploy(Trustcoin, migrationInfoSetter);
};
