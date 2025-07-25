const WalletLibrary = artifacts.require('WalletLibrary');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(WalletLibrary);
};
