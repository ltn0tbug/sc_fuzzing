const BOXToken = artifacts.require('BOXToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(BOXToken);
};
