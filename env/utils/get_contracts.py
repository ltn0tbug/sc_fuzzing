import json
import os
from web3 import Web3
import argparse


def load_compiled_contracts(artifacts_path="build/contracts"):
    """
    Load all compiled contract artifacts from Truffle's build directory.
    Extracts and returns a dictionary mapping contract names to their cleaned deployed bytecode and abi.

    Args:
        artifacts_path (str): Path to the Truffle build/contracts directory.

    Returns:
        dict: {contract_name: (deployed_bytecode, abi)}
    """
    compiled_contracts = {}

    # Iterate over all JSON artifact files
    for filename in os.listdir(artifacts_path):
        if filename.endswith(".json"):
            with open(os.path.join(artifacts_path, filename)) as f:
                data = json.load(f)
                name = data["contractName"]
                # Get deployed bytecode and strip metadata hash (after 'a264' marker)
                deployed_bytecode = data.get("deployedBytecode", "")
                abi = data.get("abi", [])
                compiled_contracts[name] = (deployed_bytecode.lower(), abi)

    return compiled_contracts


def get_contracts(ganache_rpc_url, project_path):
    """
    Retrieve all deployed contracts from a local Ganache instance for specified Truffle project.

    Connects to the specified Ganache RPC endpoint, scans all blocks for contract creation transactions, and attempts to identify each contract by matching its deployed bytecode with compiled artifacts from the given project path.

    Args:
        ganache_rpc_url (str): The HTTP RPC URL of the Ganache instance.
        project_path (str): Path to the project directory containing compiled contract artifacts.

    Returns:
        list: A list of dictionaries, each containing:
            - address (str): The deployed contract address.
            - creator (str): The address that deployed the contract.
            - creation_tx (str): The transaction hash of the contract creation.
            - contract_name (str): The identified contract name, or "Unknown" if not matched.
            - abi (list): The contract ABI, or None if not matched.
    """
    # Connect to local Ganache RPC
    w3 = Web3(Web3.HTTPProvider(ganache_rpc_url))

    # Verify connection
    if not w3.is_connected():
        raise Exception("Failed to connect to Ganache")

    # Load known compiled contract bytecode from Truffle
    compiled = load_compiled_contracts(f"{project_path}/build/contracts")
    contracts = []

    # Iterate through all blocks in the chain
    for i in range(w3.eth.block_number + 1):
        block = w3.eth.get_block(i, full_transactions=True)

        # Check each transaction in the block
        for tx in block.transactions:
            receipt = w3.eth.get_transaction_receipt(tx.hash)
            contract_address = receipt.contractAddress

            # If contractAddress is not None, this tx deployed a contract
            if contract_address:
                creator = tx["from"]
                deployed_bytecode = w3.eth.get_code(contract_address)

                # Try to identify the contract by comparing bytecode prefix
                matched_name = None
                count = 0
                for name, (deployed_bytecode_from_abi, _) in compiled.items():
                    if deployed_bytecode.to_0x_hex().lower() == deployed_bytecode_from_abi:
                        matched_name = name
                        count += 1
                
                if count > 1:
                    raise ValueError(f"There are {count} contracts have same deployed code. Please remove the duplicated complied json file.")
                
                contracts.append(
                    {
                        "address": contract_address,
                        "creator": creator,
                        "creation_tx": tx.hash.to_0x_hex(),
                        "name": matched_name or "Unknown",
                        "abi": compiled.get(matched_name, [])[1] if matched_name else None,
                    }
                )

    return contracts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan Ganache for deployed contracts and identify them.")
    parser.add_argument("--rpc", type=str, default="http://127.0.1:8545", help="Ganache RPC URL")
    parser.add_argument("--project", type=str, required=True, help="Path to Truffle project directory with build/contracts")
    args = parser.parse_args()

    ganache_rpc_url = args.rpc
    project_path = args.project
  
    print(f"Connecting to Ganache at {ganache_rpc_url}...") 
    print(f"Running contract scanner on project at {project_path}...")
    # Run the contract scanner
    contracts = get_contracts(ganache_rpc_url, project_path)

    # Display results for each contract
    for i, c in enumerate(contracts):
        print(f"\nContract {i+1}")
        print(f"Name:           {c['name']}")
        print(f"Address:        {c['address']}")
        print(f"Creator:        {c['creator']}")
        print(f"Creation TX:    {c['creation_tx']}")
        print(f"ABI (truncated): {str(c['abi'])[:60]}...")