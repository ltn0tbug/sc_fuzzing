const PredictTheBlockHashChallenge = artifacts.require("PredictTheBlockHashChallenge");

module.exports = async function (deployer, network, accounts) {
  const player = accounts[0];

  // Deploy the contract and fund it with 1 ether
  await deployer.deploy(PredictTheBlockHashChallenge, {
    from: player,
    value: web3.utils.toWei("1", "ether"),
  });
};
