const SimpleDAO = artifacts.require('SimpleDAO');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(SimpleDAO);
};
