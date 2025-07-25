const Salt = artifacts.require('Salt');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Salt);
};
