const Faythe = artifacts.require("Faythe");
const Trent = artifacts.require("Trent");
const Coinage = artifacts.require("Coinage");
const CoinageCollector = artifacts.require("CoinageCollector");

module.exports = async function (deployer, network, accounts) {
  const owner = accounts[0];

  // 1. Deploy Faythe and Trent
  await deployer.deploy(Faythe);
  const faythe = await Faythe.deployed();

  await deployer.deploy(Trent);
  const trent = await Trent.deployed();

  // 2. Deploy Coinage
  await deployer.deploy(Coinage, trent.address, faythe.address);
  const coinage = await Coinage.deployed();

  // 3. Set Coinage as contract in Faythe and Trent
  await faythe.atoshima("contract", "", coinage.address, { from: owner });
  await trent.atoshima("contract", "", coinage.address, { from: owner });

  // 4. (Optional) Deploy CoinageCollector
  await deployer.deploy(CoinageCollector, coinage.address);

  console.log("Faythe deployed at:", faythe.address);
  console.log("Trent deployed at:", trent.address);
  console.log("Coinage deployed at:", coinage.address);
};