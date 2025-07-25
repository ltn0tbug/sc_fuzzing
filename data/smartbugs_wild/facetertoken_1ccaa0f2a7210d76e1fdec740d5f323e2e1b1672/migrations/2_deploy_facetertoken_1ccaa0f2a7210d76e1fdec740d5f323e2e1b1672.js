const FaceterToken = artifacts.require("FaceterToken");

module.exports = async function (deployer, network, accounts) {
  const holderAddress = accounts[0]; // Initial token holder
  const bufferAddress = accounts[2]; // Secondary whitelisted address

  await deployer.deploy(FaceterToken, holderAddress, bufferAddress);
};
