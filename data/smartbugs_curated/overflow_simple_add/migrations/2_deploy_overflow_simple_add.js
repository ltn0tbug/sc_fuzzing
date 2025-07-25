const Overflow_Add = artifacts.require('Overflow_Add');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Overflow_Add);
};
