const IntegerOverflowMultiTxOneFuncFeasible = artifacts.require('IntegerOverflowMultiTxOneFuncFeasible');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(IntegerOverflowMultiTxOneFuncFeasible);
};
