const VEN = artifacts.require('VEN');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(VEN);
};
