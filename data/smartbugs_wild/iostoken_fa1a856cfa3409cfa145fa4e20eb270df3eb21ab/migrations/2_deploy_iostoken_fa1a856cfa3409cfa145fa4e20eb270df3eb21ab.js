const IOSToken = artifacts.require('IOSToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(IOSToken);
};
