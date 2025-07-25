const ZilliqaToken = artifacts.require("ZilliqaToken");

module.exports = function (deployer, network, accounts) {
  const admin = accounts[0]; // choose an admin address
  const totalTokenAmount = web3.utils.toBN("1000000000000000000000000"); // adjust based on desired total supply (e.g. 1 million tokens with 12 decimals)

  deployer.deploy(ZilliqaToken, admin, totalTokenAmount);
};

