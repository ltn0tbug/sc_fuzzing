const BTMC = artifacts.require('BTMC');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(BTMC);
};
