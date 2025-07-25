const HotDollarsToken = artifacts.require('HotDollarsToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(HotDollarsToken);
};
