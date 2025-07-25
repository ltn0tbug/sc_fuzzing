const VantaToken = artifacts.require('VantaToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(VantaToken);
};
