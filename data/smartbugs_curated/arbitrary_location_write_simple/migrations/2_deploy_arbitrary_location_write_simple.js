const Wallet = artifacts.require('Wallet');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Wallet);
};
