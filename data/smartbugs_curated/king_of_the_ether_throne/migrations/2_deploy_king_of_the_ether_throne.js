const KingOfTheEtherThrone = artifacts.require('KingOfTheEtherThrone');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(KingOfTheEtherThrone);
};
