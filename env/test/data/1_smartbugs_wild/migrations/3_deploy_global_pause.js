const GlobalPause = artifacts.require("GlobalPause");

module.exports = function (deployer, network, accounts) {
    deployer.deploy(GlobalPause);
};
