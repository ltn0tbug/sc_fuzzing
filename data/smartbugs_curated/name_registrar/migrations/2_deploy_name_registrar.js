const NameRegistrar = artifacts.require('NameRegistrar');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(NameRegistrar);
};
