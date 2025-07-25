const KittyCore = artifacts.require('KittyCore');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(KittyCore);
};
