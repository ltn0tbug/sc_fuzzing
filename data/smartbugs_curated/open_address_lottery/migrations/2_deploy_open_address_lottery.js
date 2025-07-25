const OpenAddressLottery = artifacts.require('OpenAddressLottery');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(OpenAddressLottery);
};
