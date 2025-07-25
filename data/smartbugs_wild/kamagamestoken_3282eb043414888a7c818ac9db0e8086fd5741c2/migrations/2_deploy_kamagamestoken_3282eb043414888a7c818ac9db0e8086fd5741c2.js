const KamaGamesToken = artifacts.require('KamaGamesToken');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(KamaGamesToken);
};
