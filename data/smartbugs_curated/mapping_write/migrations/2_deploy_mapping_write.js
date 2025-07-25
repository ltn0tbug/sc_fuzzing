const Map = artifacts.require('Map');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Map);
};
