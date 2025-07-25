const Unprotected = artifacts.require('Unprotected');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Unprotected);
};
