const Ethraffle_v4b = artifacts.require('Ethraffle_v4b');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Ethraffle_v4b);
};
