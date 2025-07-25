const Roulette = artifacts.require('Roulette');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Roulette);
};
