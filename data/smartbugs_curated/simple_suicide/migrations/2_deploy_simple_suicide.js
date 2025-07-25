const SimpleSuicide = artifacts.require('SimpleSuicide');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(SimpleSuicide);
};
