const FindThisHash = artifacts.require('FindThisHash');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(FindThisHash);
};
