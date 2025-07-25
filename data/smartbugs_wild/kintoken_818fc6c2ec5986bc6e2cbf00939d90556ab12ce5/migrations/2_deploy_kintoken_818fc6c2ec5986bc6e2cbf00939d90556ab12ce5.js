const KinToken = artifacts.require('KinToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(KinToken);
};
