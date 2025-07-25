const MCHDailyActionV2 = artifacts.require('MCHDailyActionV2');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(MCHDailyActionV2);
};
