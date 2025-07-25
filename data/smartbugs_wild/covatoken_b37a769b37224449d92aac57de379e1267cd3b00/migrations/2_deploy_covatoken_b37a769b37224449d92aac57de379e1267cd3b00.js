const CovaToken = artifacts.require('CovaToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(CovaToken);
};
