const EtherStore = artifacts.require('EtherStore');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(EtherStore);
};
