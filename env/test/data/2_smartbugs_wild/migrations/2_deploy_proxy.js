const OwnedUpgradeabilityProxy = artifacts.require("OwnedUpgradeabilityProxy");

module.exports = async function (deployer, network, accounts) {
    // Deploy the proxy contract
    await deployer.deploy(OwnedUpgradeabilityProxy);
};