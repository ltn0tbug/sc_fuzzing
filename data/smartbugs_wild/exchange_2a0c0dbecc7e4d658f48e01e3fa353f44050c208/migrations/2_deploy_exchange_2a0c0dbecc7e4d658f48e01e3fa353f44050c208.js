const Exchange = artifacts.require("Exchange");

module.exports = function (deployer, network, accounts) {
  // The fee account that will collect withdrawal/trade fees
  const feeAccount = accounts[0]; // Or replace with another address if preferred

  deployer.deploy(Exchange, feeAccount);
};