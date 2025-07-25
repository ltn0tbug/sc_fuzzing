const TetherToken = artifacts.require("TetherToken");

module.exports = function (deployer) {
  const initialSupply = web3.utils.toWei("1000000", "ether"); // 1 million tokens with 18 decimals
  const name = "Tether USD";
  const symbol = "USDT";
  const decimals = 18;
  deployer.deploy(TetherToken, initialSupply, name, symbol, decimals);
};
