const MyContract = artifacts.require('MyContract');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(MyContract);
};
