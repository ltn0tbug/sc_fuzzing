const FletaToken = artifacts.require('FletaToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(FletaToken);
};
