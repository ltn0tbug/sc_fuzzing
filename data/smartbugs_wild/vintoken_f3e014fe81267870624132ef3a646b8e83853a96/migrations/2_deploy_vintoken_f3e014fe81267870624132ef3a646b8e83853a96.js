const VinToken = artifacts.require("VinToken");

module.exports = async function (deployer, network, accounts) {
  const founder1 = accounts[2];  // Replace with actual founder address
  const founder2 = accounts[3];  // Replace with actual founder address
  const now = Math.floor(Date.now() / 1000); // current UNIX timestamp
  const icoStart = now + 60;                 // ICO starts in 1 minute
  const icoEnd = icoStart + 86400 * 30;      // ICO lasts 30 days

  await deployer.deploy(VinToken, founder1, founder2, icoStart, icoEnd);
};