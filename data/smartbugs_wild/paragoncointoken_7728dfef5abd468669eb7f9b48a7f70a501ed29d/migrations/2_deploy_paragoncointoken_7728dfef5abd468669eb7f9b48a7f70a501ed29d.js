const ParagonCoinToken = artifacts.require("ParagonCoinToken");

module.exports = async function (deployer, network, accounts) {
  // Set the fund address (can be any address you want to assign fees to)
  const fundAddress = accounts[0]; // or replace with a hardcoded address

  await deployer.deploy(ParagonCoinToken, fundAddress);
};
