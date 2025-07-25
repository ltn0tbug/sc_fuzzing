const POCToken = artifacts.require('POCToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(POCToken);
};
