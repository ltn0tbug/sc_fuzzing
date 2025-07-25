const EtherLotto = artifacts.require('EtherLotto');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(EtherLotto);
};
