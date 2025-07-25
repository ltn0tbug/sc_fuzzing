const DSToken = artifacts.require("DSToken");
const EOSSale = artifacts.require("EOSSale");

module.exports = async function (deployer, network, accounts) {

  // Configuration values
  const numberOfDays = 350;
  const totalSupply = web3.utils.toWei('1000000000', 'ether'); // 1 billion EOS
  const foundersAllocation = web3.utils.toWei('100000000', 'ether'); // 100M for founders
  const foundersKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5SoW3Rg8A1C1kHfBypM5U"; // Example

  const now = Math.floor(Date.now() / 1000);
  const openTime = now + 60;         // opens in 1 min
  const startTime = now + 3600;      // starts in 1 hour

  // Deploy the token first
  await deployer.deploy(DSToken, web3.utils.asciiToHex("EOS"));
  const eosToken = await DSToken.deployed();

  // Deploy the crowdsale
  await deployer.deploy(
    EOSSale,
    numberOfDays,
    totalSupply,
    openTime,
    startTime,
    foundersAllocation,
    foundersKey
  );

  const eosSale = await EOSSale.deployed();

  // Initialize the sale with the token
  await eosToken.setOwner(eosSale.address);       // Transfer ownership of the token to the sale
  await eosSale.initialize(eosToken.address);     // Initialize crowdsale with the token
};