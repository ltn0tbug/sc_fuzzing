const Gifto = artifacts.require('Gifto');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Gifto);
};
