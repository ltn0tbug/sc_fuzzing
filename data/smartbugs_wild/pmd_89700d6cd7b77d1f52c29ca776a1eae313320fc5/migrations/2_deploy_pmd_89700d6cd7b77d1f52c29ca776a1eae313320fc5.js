const PMD = artifacts.require('PMD');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(PMD);
};
