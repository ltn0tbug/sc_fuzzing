const MyToken = artifacts.require('MyToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(MyToken);
};
