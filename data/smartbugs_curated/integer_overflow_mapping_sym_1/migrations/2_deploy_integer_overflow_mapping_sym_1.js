const IntegerOverflowMappingSym1 = artifacts.require('IntegerOverflowMappingSym1');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(IntegerOverflowMappingSym1);
};
