const Governmental = artifacts.require("Governmental");

module.exports = async function (deployer, network, accounts) {
  const deployerAccount = accounts[0];

  // Deploy Governmental with 1 ether initial funding
  await deployer.deploy(Governmental, {
    from: deployerAccount,
    value: web3.utils.toWei("1", "ether")
  });

  const instance = await Governmental.deployed();
  console.log("Governmental deployed at:", instance.address);
};