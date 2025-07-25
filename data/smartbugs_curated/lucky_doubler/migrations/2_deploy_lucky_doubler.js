const LuckyDoubler = artifacts.require('LuckyDoubler');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(LuckyDoubler);
};
