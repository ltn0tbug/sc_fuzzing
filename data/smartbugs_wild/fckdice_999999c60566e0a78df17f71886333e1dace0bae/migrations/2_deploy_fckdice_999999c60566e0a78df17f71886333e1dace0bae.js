const FckDice = artifacts.require("FckDice");

module.exports = async function (deployer, network, accounts) {
  // Configure constructor parameters:
  const owner1 = accounts[0];
  const owner2 = accounts[2];
  const secretSigner = accounts[3]; // Off-chain bot signing commits
  const croupier = accounts[4];     // Off-chain croupier operator
  const maxProfit = web3.utils.toWei("10", "ether"); // example cap: 10 ETH

  await deployer.deploy(FckDice, owner1, owner2, secretSigner, croupier, maxProfit, {
    value: web3.utils.toWei("100", "ether") // Optional: initial bankroll
  });
};
