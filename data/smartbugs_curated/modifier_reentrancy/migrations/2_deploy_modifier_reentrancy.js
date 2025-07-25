const ModifierEntrancy = artifacts.require('ModifierEntrancy');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(ModifierEntrancy);
};
