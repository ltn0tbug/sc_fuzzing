const Rubixi = artifacts.require('Rubixi');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Rubixi);
};
