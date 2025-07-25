const GA_chain = artifacts.require('GA_chain');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(GA_chain);
};
