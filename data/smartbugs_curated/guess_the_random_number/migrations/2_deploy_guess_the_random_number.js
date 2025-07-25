const GuessTheRandomNumberChallenge = artifacts.require('GuessTheRandomNumberChallenge');

module.exports = function (deployer, network, accounts) {
  const player = accounts[0];

  // Deploy and send 1 ether to the constructor
  deployer.deploy(GuessTheRandomNumberChallenge, {
    from: player,
    value: web3.utils.toWei("1", "ether"),
  });
};
