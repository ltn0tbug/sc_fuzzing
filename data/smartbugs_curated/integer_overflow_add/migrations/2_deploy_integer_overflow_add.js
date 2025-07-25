const IntegerOverflowAdd = artifacts.require('IntegerOverflowAdd');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(IntegerOverflowAdd);
};
