const SPNToken = artifacts.require('SPNToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(SPNToken);
};
