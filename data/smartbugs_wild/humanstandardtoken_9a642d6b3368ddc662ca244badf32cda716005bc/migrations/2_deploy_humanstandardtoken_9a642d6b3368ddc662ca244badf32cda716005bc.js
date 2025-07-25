const HumanStandardToken = artifacts.require("HumanStandardToken");

module.exports = async function (deployer, network, accounts) {
  // Parameters for the HumanStandardToken constructor
  const initialAmount = 1000000;         // Total supply (raw units, no decimals applied yet)
  const tokenName = "Human Token";       // Token name
  const decimalUnits = 18;               // Number of decimal places
  const tokenSymbol = "HUM";             // Token symbol

  await deployer.deploy(HumanStandardToken, initialAmount, tokenName, decimalUnits, tokenSymbol);
};
