const Amplify = artifacts.require('Amplify');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(Amplify);
};
