const Proxy = artifacts.require('Proxy');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Proxy);
};
