const LoopringToken = artifacts.require('LoopringToken');

module.exports = function (deployer, network, accounts) {
  const targetAddress = accounts[0]
  deployer.deploy(LoopringToken, targetAddress);
};
