const CanYaCoin = artifacts.require('CanYaCoin');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(CanYaCoin);
};
