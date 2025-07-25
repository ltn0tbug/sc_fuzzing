const MyAdvancedToken = artifacts.require('MyAdvancedToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(MyAdvancedToken);
};
