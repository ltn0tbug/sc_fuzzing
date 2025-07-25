const FCS = artifacts.require('FCS');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(FCS);
};
