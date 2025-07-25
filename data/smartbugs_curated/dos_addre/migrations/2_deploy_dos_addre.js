const DosGas = artifacts.require('DosGas');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(DosGas);
};
