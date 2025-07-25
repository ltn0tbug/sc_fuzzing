const AdBank = artifacts.require('AdBank');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(AdBank);
};
