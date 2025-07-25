const CentrallyIssuedToken = artifacts.require("CentrallyIssuedToken");

module.exports = async function (deployer, network, accounts) {
  const owner = accounts[0]; // The account that will receive the initial supply
  const name = "My Token";   // Replace with your token's name
  const symbol = "MTK";      // Replace with your token's symbol
  const decimals = 18;       // Usually 18 for ERC-20
  const totalSupply = web3.utils.toWei("1000000", "ether"); // 1 million tokens (with 18 decimals)

  await deployer.deploy(CentrallyIssuedToken, owner, name, symbol, totalSupply, decimals);
};
