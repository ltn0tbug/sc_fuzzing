const DepositAddressRegistrar = artifacts.require("DepositAddressRegistrar");

module.exports = async function (deployer, network, accounts) {
    const registryAddress = accounts[0]; // Using deployer's address as mock Registry
    await deployer.deploy(DepositAddressRegistrar, registryAddress);
};