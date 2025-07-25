const IntegerOverflowMultiTxMultiFuncFeasible = artifacts.require('IntegerOverflowMultiTxMultiFuncFeasible');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(IntegerOverflowMultiTxMultiFuncFeasible);
};
