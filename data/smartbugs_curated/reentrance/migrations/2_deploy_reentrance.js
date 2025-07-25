const Reentrance = artifacts.require('Reentrance');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Reentrance);
};
