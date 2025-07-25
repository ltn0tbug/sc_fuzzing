const ERC20Token = artifacts.require('ERC20Token');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(ERC20Token);
};
