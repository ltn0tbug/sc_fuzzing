const EToken2 = artifacts.require('EToken2');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(EToken2);
};
