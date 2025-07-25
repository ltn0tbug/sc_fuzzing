const MeetOneToken = artifacts.require('MeetOneToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(MeetOneToken);
};
