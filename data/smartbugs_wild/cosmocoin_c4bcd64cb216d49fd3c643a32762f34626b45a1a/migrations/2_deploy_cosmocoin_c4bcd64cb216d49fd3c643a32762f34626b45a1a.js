const CosmoCoin = artifacts.require("CosmoCoin");

module.exports = async function (deployer, network, accounts) {
  // Assign addresses
  const icoAddress = accounts[2];    // You can adjust this
  const adminAddress = accounts[3];  // You can adjust this

  await deployer.deploy(CosmoCoin, icoAddress, adminAddress);
};
