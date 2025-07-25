const BNB = artifacts.require("BNB");

module.exports = function (deployer) {
  const initialSupply = web3.utils.toWei("1000000", "ether"); // 1 million tokens with 18 decimals
  const tokenName = "BinanceCoin";
  const tokenDecimals = 18;
  const tokenSymbol = "BNB";

  deployer.deploy(BNB, initialSupply, tokenName, tokenDecimals, tokenSymbol);
};
