const ZerochainToken = artifacts.require('ZerochainToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(ZerochainToken);
};
