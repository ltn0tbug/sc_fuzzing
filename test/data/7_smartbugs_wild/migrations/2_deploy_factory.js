const ImmutableCreate2Factory = artifacts.require("ImmutableCreate2Factory");

module.exports = async function (deployer, network, accounts) {
    await deployer.deploy(ImmutableCreate2Factory);
};