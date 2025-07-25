const ERC20 = artifacts.require("ERC20");

module.exports = function (deployer) {
  const initialSupply = web3.utils.toWei('1000', 'ether'); // Replace with your desired initial supply
  deployer.deploy(ERC20, initialSupply);
};