const FibonacciLib = artifacts.require("FibonacciLib");
const FibonacciBalance = artifacts.require("FibonacciBalance");

module.exports = async function (deployer) {
  // Deploy the FibonacciLib contract
  await deployer.deploy(FibonacciLib);
  const libInstance = await FibonacciLib.deployed();

  // Deploy FibonacciBalance with the library address and send some ETH
  await deployer.deploy(FibonacciBalance, libInstance.address, {
    value: web3.utils.toWei("10", "ether"), // Optional initial ETH
  });
};