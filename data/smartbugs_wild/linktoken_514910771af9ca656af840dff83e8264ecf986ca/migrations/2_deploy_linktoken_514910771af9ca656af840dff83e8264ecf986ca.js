const LinkToken = artifacts.require('LinkToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(LinkToken);
};
