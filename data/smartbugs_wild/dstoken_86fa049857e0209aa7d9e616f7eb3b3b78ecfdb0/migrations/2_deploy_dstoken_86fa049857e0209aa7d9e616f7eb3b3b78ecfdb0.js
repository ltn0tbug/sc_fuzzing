const DSToken = artifacts.require("DSToken");

module.exports = async function (deployer) {
  const symbol = web3.utils.fromAscii("MKR"); // Replace with your token symbol

  await deployer.deploy(DSToken, symbol);
};
