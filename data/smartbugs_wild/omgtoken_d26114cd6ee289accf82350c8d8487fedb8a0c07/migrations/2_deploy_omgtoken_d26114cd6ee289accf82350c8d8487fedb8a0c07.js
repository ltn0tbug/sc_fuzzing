const OMGToken = artifacts.require('OMGToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(OMGToken);
};
