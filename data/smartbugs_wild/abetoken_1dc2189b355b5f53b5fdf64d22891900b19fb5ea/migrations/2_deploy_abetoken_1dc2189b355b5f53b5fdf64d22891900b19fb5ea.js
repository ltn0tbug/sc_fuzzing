const ABEToken = artifacts.require('ABEToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(ABEToken);
};
