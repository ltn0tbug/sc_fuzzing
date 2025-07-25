const HydroToken = artifacts.require('HydroToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(HydroToken);
};
