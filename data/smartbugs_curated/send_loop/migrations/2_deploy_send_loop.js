const Refunder = artifacts.require('Refunder');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Refunder);
};
