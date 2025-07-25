const NamCoin = artifacts.require("NamCoin");

module.exports = function (deployer, network, accounts) {
  const fundsWallet = accounts[0]; // Replace with desired wallet address or leave as is for testing

  deployer.deploy(NamCoin, fundsWallet);
};
