const NumeraireBackend = artifacts.require("NumeraireBackend");

module.exports = async function (deployer, network, accounts) {
  // Define multisig owners
  const owners = [
    accounts[0], // Replace or expand this list as needed
    accounts[2],
    accounts[3]
  ];

  // Required number of signatures
  const requiredSignatures = 2;

  // Initial disbursement (e.g., 1 million NMR with 18 decimals)
  const initialDisbursement = web3.utils.toWei("1000000", "ether");

  await deployer.deploy(
    NumeraireBackend,
    owners,
    requiredSignatures,
    initialDisbursement
  );
};
