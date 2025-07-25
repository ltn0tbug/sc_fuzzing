const PayToken = artifacts.require('PayToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(PayToken);
};
