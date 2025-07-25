const Rouleth = artifacts.require('Rouleth');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Rouleth);
};
