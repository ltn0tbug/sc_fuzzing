const Overflow = artifacts.require('Overflow');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Overflow);
};
