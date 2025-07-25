const AEToken = artifacts.require('AEToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(AEToken);
};
