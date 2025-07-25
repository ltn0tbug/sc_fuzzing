const LBN = artifacts.require('LBN');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(LBN);
};
