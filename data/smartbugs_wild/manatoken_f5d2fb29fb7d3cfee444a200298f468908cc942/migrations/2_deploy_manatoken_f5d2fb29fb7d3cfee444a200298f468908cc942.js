const MANAToken = artifacts.require('MANAToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(MANAToken);
};
