const DosAuction = artifacts.require('DosAuction');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(DosAuction);
};
