const INSToken = artifacts.require('INSToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(INSToken);
};
