const SCFToken = artifacts.require('SCFToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(SCFToken);
};
