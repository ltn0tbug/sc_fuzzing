const SimpleChildToken = artifacts.require("SimpleChildToken");

module.exports = function (deployer, network, accounts) {
  const owner = accounts[0];
  const name = "MyChildToken";
  const symbol = "MCT";
  const initialSupply = web3.utils.toBN("1000000000000000000000000"); // 1 million tokens, assuming 18 decimals
  const decimals = 18;

  deployer.deploy(SimpleChildToken, owner, name, symbol, initialSupply, decimals);
};
