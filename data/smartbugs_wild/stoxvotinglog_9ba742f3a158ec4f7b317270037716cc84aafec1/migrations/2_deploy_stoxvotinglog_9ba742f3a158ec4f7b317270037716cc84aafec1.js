const StoxVotingLog = artifacts.require('StoxVotingLog');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(StoxVotingLog);
};
