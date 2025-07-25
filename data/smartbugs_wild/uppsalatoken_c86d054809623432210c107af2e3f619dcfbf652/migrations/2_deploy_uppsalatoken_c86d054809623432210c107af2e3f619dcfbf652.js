const UppsalaToken = artifacts.require('UppsalaToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(UppsalaToken);
};
