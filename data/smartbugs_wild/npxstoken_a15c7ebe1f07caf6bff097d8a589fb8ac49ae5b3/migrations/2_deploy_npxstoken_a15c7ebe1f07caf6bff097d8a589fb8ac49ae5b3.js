const NPXSToken = artifacts.require('NPXSToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(NPXSToken);
};
