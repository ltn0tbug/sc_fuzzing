const ZRXToken = artifacts.require('ZRXToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(ZRXToken);
};
