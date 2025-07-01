const GlobalPause = artifacts.require("GlobalPause");

module.exports = function (deployer) {
    deployer.deploy(GlobalPause);
};
