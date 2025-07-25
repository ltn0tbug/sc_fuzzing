const TuzyCoin = artifacts.require('TuzyCoin');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(TuzyCoin);
};
