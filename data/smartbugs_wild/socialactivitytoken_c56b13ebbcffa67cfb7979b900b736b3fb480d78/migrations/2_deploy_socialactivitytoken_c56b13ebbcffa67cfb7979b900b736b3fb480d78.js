const SocialActivityToken = artifacts.require('SocialActivityToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(SocialActivityToken);
};
