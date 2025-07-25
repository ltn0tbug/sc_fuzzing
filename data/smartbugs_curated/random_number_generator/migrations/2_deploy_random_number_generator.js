const RandomNumberGenerator = artifacts.require('RandomNumberGenerator');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(RandomNumberGenerator);
};
