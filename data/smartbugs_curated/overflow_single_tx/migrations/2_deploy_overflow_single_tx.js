const IntegerOverflowSingleTransaction = artifacts.require('IntegerOverflowSingleTransaction');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(IntegerOverflowSingleTransaction);
};
