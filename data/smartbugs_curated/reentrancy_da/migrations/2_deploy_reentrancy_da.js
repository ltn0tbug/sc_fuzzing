const ReentrancyDAO = artifacts.require('ReentrancyDAO');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(ReentrancyDAO);
};
