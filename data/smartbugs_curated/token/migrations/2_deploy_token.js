const Token = artifacts.require('Token');

module.exports = function (deployer, network, accounts) {
  const initialSupply = 1000000; // Adjust as needed
  deployer.deploy(Token, initialSupply);
};
