const HBToken = artifacts.require('HBToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(HBToken);
};
