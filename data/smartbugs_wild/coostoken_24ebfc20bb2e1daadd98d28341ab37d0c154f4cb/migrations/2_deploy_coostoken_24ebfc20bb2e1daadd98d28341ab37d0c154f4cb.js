const COOSToken = artifacts.require("COOSToken");

module.exports = async function (deployer) {
  const initialSupply = web3.utils.toWei("1000000", "ether"); // 1,000,000 tokens with 18 decimals
  const name = "COOS Token";
  const symbol = "COOS";

  await deployer.deploy(COOSToken, initialSupply, name, symbol);
};
