const Controller = artifacts.require('Controller');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Controller);
};
