const ReplaySafeSplit = artifacts.require('ReplaySafeSplit');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(ReplaySafeSplit);
};
