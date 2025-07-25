const LedgerChannel = artifacts.require("LedgerChannel");
const HumanStandardToken = artifacts.require("HumanStandardToken");

module.exports = async function (deployer, network, accounts) {
  const initialSupply = web3.utils.toWei('1000000', 'ether'); // 1 million tokens
  const tokenName = "Test Token";
  const tokenDecimals = 18;
  const tokenSymbol = "TST";

  // Deploy HumanStandardToken
  await deployer.deploy(HumanStandardToken, initialSupply, tokenName, tokenDecimals, tokenSymbol);
  const tokenInstance = await HumanStandardToken.deployed();

  // Deploy LedgerChannel
  await deployer.deploy(LedgerChannel);

  console.log("Token Address:", tokenInstance.address);
};