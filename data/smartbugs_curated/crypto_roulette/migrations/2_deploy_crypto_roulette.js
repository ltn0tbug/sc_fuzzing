const CryptoRoulette = artifacts.require('CryptoRoulette');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(CryptoRoulette);
};
