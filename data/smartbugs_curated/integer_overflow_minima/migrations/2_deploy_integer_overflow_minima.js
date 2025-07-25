const IntegerOverflowMinimal = artifacts.require('IntegerOverflowMinimal');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(IntegerOverflowMinimal);
};
