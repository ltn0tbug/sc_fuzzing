const EthTxOrderDependenceMinimal = artifacts.require('EthTxOrderDependenceMinimal');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(EthTxOrderDependenceMinimal);
};
