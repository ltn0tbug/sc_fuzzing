const Missing = artifacts.require('Missing');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Missing);
};
