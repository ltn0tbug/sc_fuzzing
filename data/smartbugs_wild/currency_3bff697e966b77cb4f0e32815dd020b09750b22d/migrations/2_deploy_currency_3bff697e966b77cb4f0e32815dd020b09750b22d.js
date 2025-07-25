const Currency = artifacts.require("Currency");

module.exports = async function (deployer, network, accounts) {
  // Deployment parameters
  const deployerAddress = accounts[0]; // Initial holder of tokens
  const initialSupply = 1000000;       // Change to your desired initial token supply
  const tokenName = "MyToken";         // Change to your token's name
  const tokenSymbol = "MTK";           // Change to your token's symbol

  await deployer.deploy(Currency, deployerAddress, initialSupply, tokenName, tokenSymbol);
};
