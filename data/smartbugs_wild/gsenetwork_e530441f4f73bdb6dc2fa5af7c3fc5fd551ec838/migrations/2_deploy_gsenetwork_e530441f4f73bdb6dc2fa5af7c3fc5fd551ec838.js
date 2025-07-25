const GSENetwork = artifacts.require('GSENetwork');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(GSENetwork);
};
