const OwnedUpgradeabilityProxy = artifacts.require('OwnedUpgradeabilityProxy');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(OwnedUpgradeabilityProxy);
};
