const DebitumToken = artifacts.require('DebitumToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(DebitumToken);
};
