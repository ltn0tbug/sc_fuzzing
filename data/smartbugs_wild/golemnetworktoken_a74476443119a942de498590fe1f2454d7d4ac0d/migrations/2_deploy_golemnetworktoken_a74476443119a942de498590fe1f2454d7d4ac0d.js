const GolemNetworkToken = artifacts.require("GolemNetworkToken");

module.exports = async function (deployer, network, accounts) {
  const golemFactory = accounts[0];        // Receives ETH and tokens
  const migrationMaster = accounts[2];     // Can set migration agent

  // Use await to fetch block number properly
  const currentBlock = await web3.eth.getBlockNumber();
  const fundingStartBlock = currentBlock + 10;
  const fundingEndBlock = fundingStartBlock + 200;

  await deployer.deploy(
    GolemNetworkToken,
    golemFactory,
    migrationMaster,
    fundingStartBlock,
    fundingEndBlock
  );
};