const SmartBillions = artifacts.require('SmartBillions');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(SmartBillions);
};
