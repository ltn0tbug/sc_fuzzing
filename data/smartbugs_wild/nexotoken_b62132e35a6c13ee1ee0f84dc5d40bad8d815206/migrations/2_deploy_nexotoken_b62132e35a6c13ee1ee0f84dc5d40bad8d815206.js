const NexoToken = artifacts.require('NexoToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(NexoToken);
};
