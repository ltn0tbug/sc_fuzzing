const Metapod = artifacts.require("Metapod");

module.exports = function (deployer, network, accounts) {
    deployer.deploy(Metapod);
};
