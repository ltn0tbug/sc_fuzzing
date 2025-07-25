const OmixToken = artifacts.require("OmixToken");

module.exports = function (deployer) {
  const initialSupply = web3.utils.toBN("100000000000000000"); // example: 1 billion tokens with 8 decimals

  deployer.deploy(OmixToken, initialSupply);
};
