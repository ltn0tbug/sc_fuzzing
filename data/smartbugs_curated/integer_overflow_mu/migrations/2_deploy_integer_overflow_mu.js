const IntegerOverflowMul = artifacts.require('IntegerOverflowMul');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(IntegerOverflowMul);
};
