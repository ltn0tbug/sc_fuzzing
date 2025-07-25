const Lotto = artifacts.require('Lotto');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Lotto);
};
