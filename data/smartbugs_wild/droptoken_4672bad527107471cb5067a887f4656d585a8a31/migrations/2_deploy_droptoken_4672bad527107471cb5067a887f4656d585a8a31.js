const DropToken = artifacts.require('DropToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(DropToken);
};
