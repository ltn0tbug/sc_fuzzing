const FriendzToken = artifacts.require("FriendzToken");

module.exports = async function (deployer, network, accounts) {
  // Customize these values according to your needs
  const name = "Friendz Token";
  const symbol = "FDZ";
  const decimals = 18;
  const supply = web3.utils.toWei("1000000000", "ether"); // 1B tokens with 18 decimals

  await deployer.deploy(FriendzToken, name, symbol, decimals, supply);
};
