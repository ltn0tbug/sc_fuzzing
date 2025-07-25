const Hourglass = artifacts.require('Hourglass');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Hourglass);
};
