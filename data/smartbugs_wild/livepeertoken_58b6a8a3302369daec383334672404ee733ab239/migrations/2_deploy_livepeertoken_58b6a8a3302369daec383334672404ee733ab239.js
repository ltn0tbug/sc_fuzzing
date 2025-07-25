const LivepeerToken = artifacts.require('LivepeerToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(LivepeerToken);
};
