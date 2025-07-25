const TimedCrowdsale = artifacts.require('TimedCrowdsale');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(TimedCrowdsale);
};
