const WETH9 = artifacts.require('WETH9');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(WETH9);
};
