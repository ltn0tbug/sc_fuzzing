const DIVXToken = artifacts.require("DIVXToken");

module.exports = async function (deployer, network, accounts) {
  // Example parameters
  const fundDeposit = accounts[0];

  // Dummy block numbers – adjust for your actual deployment plan
  const fundingStartBlock = 100;    // e.g., current block + N
  const firstXRChangeBlock = 200;
  const secondXRChangeBlock = 300;
  const thirdXRChangeBlock = 400;
  const fundingEndBlock = 500;

  await deployer.deploy(
    DIVXToken,
    fundDeposit,
    fundingStartBlock,
    firstXRChangeBlock,
    secondXRChangeBlock,
    thirdXRChangeBlock,
    fundingEndBlock
  );
};
