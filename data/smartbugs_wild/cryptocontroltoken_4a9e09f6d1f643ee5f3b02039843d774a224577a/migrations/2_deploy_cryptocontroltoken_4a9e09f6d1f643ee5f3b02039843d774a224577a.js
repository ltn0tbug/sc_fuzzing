const CryptoControlToken = artifacts.require('CryptoControlToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(CryptoControlToken);
};
