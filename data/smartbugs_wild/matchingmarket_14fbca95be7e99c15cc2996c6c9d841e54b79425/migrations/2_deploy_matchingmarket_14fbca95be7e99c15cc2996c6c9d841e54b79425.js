// migrations/2_deploy_market.js
const MatchingMarket = artifacts.require("MatchingMarket");

module.exports = async function (deployer, network, accounts) {
  const owner = accounts[0];

  // Set an appropriate close time (UNIX timestamp) for your market
  // Example: 30 days from now
  const now = Math.floor(Date.now() / 1000);
  const closeTime = now + 30 * 24 * 60 * 60;

  // Deploy MatchingMarket
  await deployer.deploy(MatchingMarket, closeTime, { from: owner });
  const market = await MatchingMarket.deployed();

  console.log("MatchingMarket deployed at:", market.address);

  // Optionally, set authority (privileged contracts) using DSAuth.
  // const someAuthority = /* authority contract instance */;
  // await market.setAuthority(someAuthority.address, { from: owner });

  // Optionally, whitelist a token pair:
  // await market.addTokenPairWhitelist(tokenA.address, tokenB.address, { from: owner });
};
