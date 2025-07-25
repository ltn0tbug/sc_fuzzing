const OCoin = artifacts.require('OCoin');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(OCoin);
};
