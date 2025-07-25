const PFC = artifacts.require('PFC');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(PFC);
};
