const AergoToken = artifacts.require('AergoToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(AergoToken);
};
