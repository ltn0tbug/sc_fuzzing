const Bitcoinereum = artifacts.require('Bitcoinereum');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Bitcoinereum);
};
