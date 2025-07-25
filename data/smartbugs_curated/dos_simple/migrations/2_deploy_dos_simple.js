const DosOneFunc = artifacts.require('DosOneFunc');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(DosOneFunc);
};
