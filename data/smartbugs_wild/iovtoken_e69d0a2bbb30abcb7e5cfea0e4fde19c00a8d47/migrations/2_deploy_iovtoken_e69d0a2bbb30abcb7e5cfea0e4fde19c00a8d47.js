const IOVToken = artifacts.require("IOVToken");

module.exports = function (deployer) {
  const symbol = "IOV";
  deployer.deploy(IOVToken, symbol);
};