const Phishable = artifacts.require('Phishable');

module.exports = function (deployer, network, accounts) {
  const owners = accounts[0]; // Use deployer's address
  deployer.deploy(Phishable, owners);
};
