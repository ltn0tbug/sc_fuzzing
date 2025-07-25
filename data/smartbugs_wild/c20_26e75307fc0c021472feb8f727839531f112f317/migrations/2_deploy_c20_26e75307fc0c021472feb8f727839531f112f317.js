const C20 = artifacts.require("C20");

module.exports = async function (deployer, network, accounts) {
  const fundWallet = accounts[0];          // Deploying address becomes the fundWallet
  const controlWallet = accounts[2];       // Set control wallet to a separate address
  const priceNumerator = 1000;             // 1 token = 1 USD (numerator of the price)
  const currentBlock = await web3.eth.getBlockNumber();
  const startBlock = currentBlock + 10;    // Sale starts in 10 blocks
  const endBlock = startBlock + 50000;     // Sale ends 50,000 blocks later

  await deployer.deploy(
    C20,
    controlWallet,
    priceNumerator,
    startBlock,
    endBlock
  );
};
