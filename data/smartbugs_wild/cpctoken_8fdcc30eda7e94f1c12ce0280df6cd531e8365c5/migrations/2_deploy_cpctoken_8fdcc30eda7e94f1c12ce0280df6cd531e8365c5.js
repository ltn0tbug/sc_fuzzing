const CpcToken = artifacts.require('CpcToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(CpcToken);
};
