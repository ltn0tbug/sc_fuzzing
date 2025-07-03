const ExtendedJurisdiction = artifacts.require("ExtendedJurisdiction");

module.exports = async function (deployer, network, accounts) {
    await deployer.deploy(ExtendedJurisdiction);
};