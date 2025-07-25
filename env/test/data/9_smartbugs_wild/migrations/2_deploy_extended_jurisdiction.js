const ExtendedJurisdiction = artifacts.require("ExtendedJurisdiction");

module.exports = async function (deployer, network, accounts) {
    const owner = accounts[0]; // you can modify this to any address you want as the initial owner

    await deployer.deploy(ExtendedJurisdiction, owner);
};