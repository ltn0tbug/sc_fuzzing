const DailyAction = artifacts.require('DailyAction');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(DailyAction);
};
