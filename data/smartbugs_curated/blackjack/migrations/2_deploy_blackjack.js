const BlackJack = artifacts.require('BlackJack');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(BlackJack);
};
