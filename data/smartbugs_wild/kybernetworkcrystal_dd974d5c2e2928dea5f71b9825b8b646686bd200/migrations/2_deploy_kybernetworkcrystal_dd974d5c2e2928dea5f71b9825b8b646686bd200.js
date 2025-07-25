const KyberNetworkCrystal = artifacts.require("KyberNetworkCrystal");

module.exports = function (deployer, network, accounts) {
  // Configuration (you can adjust these values as needed)
  const totalSupply = web3.utils.toWei('226000000', 'ether'); // assuming 226 million KNC with 18 decimals
  const saleStartTime = Math.floor(Date.now() / 1000); // current block timestamp
  const saleEndTime = saleStartTime + (60 * 60 * 24 * 30); // 30 days from start
  const admin = accounts[0]; // deployer as admin, or choose another

  deployer.deploy(KyberNetworkCrystal, totalSupply, saleStartTime, saleEndTime, admin);
};
