const MiracleTeleToken = artifacts.require("MiracleTeleToken");

module.exports = async function (deployer, network, accounts) {
  const initialSupply = 100000000; // Example: 100 million TELE tokens

  await deployer.deploy(MiracleTeleToken, initialSupply);
};
