const PumaPayToken = artifacts.require('PumaPayToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(PumaPayToken);
};
