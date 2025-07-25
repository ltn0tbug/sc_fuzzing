const LockChain = artifacts.require('LockChain');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(LockChain);
};
