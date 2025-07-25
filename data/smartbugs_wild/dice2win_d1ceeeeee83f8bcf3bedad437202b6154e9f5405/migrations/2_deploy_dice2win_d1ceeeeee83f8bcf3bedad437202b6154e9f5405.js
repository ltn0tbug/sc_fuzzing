const Dice2Win = artifacts.require('Dice2Win');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Dice2Win);
};
