const IntegerOverflowBenign1 = artifacts.require('IntegerOverflowBenign1');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(IntegerOverflowBenign1);
};
