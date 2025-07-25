const TokenStore = artifacts.require("TokenStore");

module.exports = async function (deployer, network, accounts) {
  const initialFee = web3.utils.toWei('0.002', 'ether'); // 0.2% fee
  const predecessor = '0x0000000000000000000000000000000000000000'; // no predecessor on first deployment

  await deployer.deploy(TokenStore, initialFee, predecessor);
};
