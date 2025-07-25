const ReturnValue = artifacts.require('ReturnValue');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(ReturnValue);
};
