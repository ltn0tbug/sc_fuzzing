const MultiSigWallet = artifacts.require("MultiSigWallet");

module.exports = async function (deployer, network, accounts) {
    const owners = [accounts[0]]; // Use deployer's address
    const requiredConfirmations = 1;

    await deployer.deploy(MultiSigWallet, owners, requiredConfirmations);
};