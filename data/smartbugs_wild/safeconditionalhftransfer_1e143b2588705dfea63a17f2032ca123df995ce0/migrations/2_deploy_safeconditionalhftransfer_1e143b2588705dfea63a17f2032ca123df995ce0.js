const SafeConditionalHFTransfer = artifacts.require('SafeConditionalHFTransfer');

module.exports = function (deployer, network, accounts) {
  deployer.deploy(SafeConditionalHFTransfer);
};
