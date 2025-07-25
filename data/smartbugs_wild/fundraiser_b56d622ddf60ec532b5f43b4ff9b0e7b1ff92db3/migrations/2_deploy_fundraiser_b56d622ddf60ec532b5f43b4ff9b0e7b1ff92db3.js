const Fundraiser = artifacts.require("Fundraiser");

module.exports = async function (deployer, network, accounts) {
  // You can modify these addresses as needed
  const signer1 = accounts[2];
  const signer2 = accounts[3];

  await deployer.deploy(Fundraiser, signer1, signer2);
};
