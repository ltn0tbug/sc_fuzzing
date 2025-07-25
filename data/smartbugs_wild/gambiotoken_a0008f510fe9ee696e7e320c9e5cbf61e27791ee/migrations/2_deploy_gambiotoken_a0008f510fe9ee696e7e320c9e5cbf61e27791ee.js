const GambioToken = artifacts.require("GambioToken");

module.exports = async function (deployer, network, accounts) {
  // Customize these parameters
  const burner = accounts[0];                 // Address with burn rights
  const cap = web3.utils.toWei('100000000', 'ether'); // 100 million tokens with 18 decimals

  await deployer.deploy(GambioToken, burner, cap);
};
