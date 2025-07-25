const TokenSaleChallenge = artifacts.require('TokenSaleChallenge');

module.exports = function (deployer, network, accounts) {
  const player = accounts[0];

  // Send exactly 1 ether to the constructor
  deployer.deploy(TokenSaleChallenge, player, {
    from: player,
    value: web3.utils.toWei("1", "ether"),
  });
};
