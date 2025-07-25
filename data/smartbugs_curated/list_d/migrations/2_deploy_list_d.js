const Government = artifacts.require('Government');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Government);
};
