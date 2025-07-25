const AVINOCToken = artifacts.require('AVINOCToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(AVINOCToken);
};
