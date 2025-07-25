const TimeLock = artifacts.require('TimeLock');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(TimeLock);
};
