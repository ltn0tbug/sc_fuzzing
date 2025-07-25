const MCAP = artifacts.require("MCAP");

module.exports = async function (deployer, network, accounts) {
  const initialSupply = 1000000;         // Change to your desired initial supply
  const tokenName = "MCAP Token";        // Token name
  const decimalUnits = 18;               // Number of decimals
  const tokenSymbol = "MCAP";            // Symbol

  await deployer.deploy(MCAP, initialSupply, tokenName, decimalUnits, tokenSymbol);
};
