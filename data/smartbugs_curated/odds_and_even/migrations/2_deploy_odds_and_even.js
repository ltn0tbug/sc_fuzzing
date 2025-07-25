const OddsAndEvens = artifacts.require('OddsAndEvens');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(OddsAndEvens);
};
