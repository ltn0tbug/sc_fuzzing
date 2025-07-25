const TestContract = artifacts.require('TestContract');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(TestContract);
};
