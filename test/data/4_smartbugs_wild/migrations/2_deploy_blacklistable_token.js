const TokenStore = artifacts.require("TokenStore");
const BlacklistStore = artifacts.require("BlacklistStore");
const BlacklistableToken = artifacts.require("BlacklistableToken");

module.exports = async function (deployer, network, accounts) {
    const deployerAccount = accounts[0];

    // 1. Deploy TokenStore
    await deployer.deploy(TokenStore);
    const tokenStore = await TokenStore.deployed();

    // 2. Deploy BlacklistStore
    await deployer.deploy(BlacklistStore);
    const blacklistStore = await BlacklistStore.deployed();

    // 3. Deploy BlacklistableToken
    await deployer.deploy(BlacklistableToken);
    const token = await BlacklistableToken.deployed();

    // 4. Set TokenStore in token
    await token.setTokenStore(tokenStore.address);

    // 5. Set BlacklistStore in token
    await token.setBlacklistStore(blacklistStore.address);

    // 6. Transfer ownership of TokenStore to token contract
    await tokenStore.transferOwnership(token.address);
    await token.claimOwnership();

    // 7. Transfer ownership of BlacklistStore to token contract
    await blacklistStore.transferOwnership(token.address);
    await blacklistStore.claimOwnership();

    // 8. Set operator, pauser, blacklister (all as deployerAccount initially)
    await token.updateOperator(deployerAccount);
    await token.updatePauser(deployerAccount);
    await token.updateBlacklister(deployerAccount);
};