const DosNumber = artifacts.require('DosNumber');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(DosNumber);
};
