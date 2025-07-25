const ZeusShieldCoin = artifacts.require('ZeusShieldCoin');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(ZeusShieldCoin);
};
