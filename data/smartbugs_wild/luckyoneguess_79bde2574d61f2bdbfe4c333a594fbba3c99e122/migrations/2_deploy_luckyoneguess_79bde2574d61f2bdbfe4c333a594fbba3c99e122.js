const LuckyoneGuess = artifacts.require('LuckyoneGuess');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(LuckyoneGuess);
};
