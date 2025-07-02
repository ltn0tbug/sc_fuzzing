from .utils import *
from .blockchain import Ganache
import argparse

class Contract:
    def __init__(self, name, address, creator, creation_tx, bytecode, abi):
        self.name = name
        self.address = address
        self.creator = creator
        self.creation_tx = creation_tx
        self.bytecode = bytecode
        self.abi = abi

    def __repr__(self):
        return f"Contract(address={self.address[:10]}, name={self.name}, creator={self.creator[:10]}, creation_tx={self.creation_tx[:10]})"
    
    def to_dict(self):
        return {
            "name": self.name,
            "address": self.address,
            "creator": self.creator,
            "creation_tx": self.creation_tx,
            "bytecode": self.bytecode,
            "abi": self.abi
        }

class Account:
    def __init__(self, address, private_key, balance, nonce):
        self.address = address
        self.private_key = private_key
        self.balance = balance
        self.nonce = nonce

    def __repr__(self):
        return f"Account(address={self.address.hex()[:10]}, balance={self.balance:,} Wei)"
    
    def to_dict(self):
        return {
            "address": self.address,
            "private_key": self.private_key,
            "balance": self.balance,
            "nonce": self.nonce
        }

class Env:
    def __init__(self, ganache: Ganache, project_path: str):
        """
        Initializes the environment with a Ganache instance and a Truffle project path.
        Args:
            ganache (Ganache): An instance of the Ganache class to manage the local blockchain.
            project_path (str): Path to the Truffle project directory.
        Raises:
            ValueError: If the provided project path is not a valid Truffle project.
        """
        if not is_truffle_project(project_path):
            raise ValueError(f"Invalid Truffle project path provided ({project_path})")
        self.project_path = project_path
        self.ganache = ganache
        self.truffle_config = {
            "host": "127.0.0.1",
            "port": 8545,
            "network_id": "*"
        }

    def init(self):
        """
        Initializes the Truffle/Ganache environment by starting Ganache, compiling the Truffle project,
        and migrating the contracts to the local Ganache instance.
        """

        # Init Ganache
        log("Initializing environment...", "info")
        log("Initializing Ganache...", "info")
        self.start_ganache()
        
        # Init Truffle
        log("Update Truffle configuration...", "info")
        self.add_truffle_config()
        log("Running Truffle compile...", "info")
        self.run_truffle_compile()
        log("Running Truffle migrate...", "info")
        self.run_truffle_migrate()
    
    def start_ganache(self):
        self.ganache.start()
    
    def stop_ganache(self):
        self.ganache.stop()

    def run_truffle_compile(self):
        """
        Runs the Truffle compile command to compile the smart contracts in the project.
        """
        run_truffle_compile(self.project_path)

    def run_truffle_migrate(self):
        """
        Runs the Truffle migrate command to deploy the compiled contracts to the local Ganache instance.
        """
        run_truffle_migrate(self.project_path)

    def run_truffle_version(self):
        """
        Runs the Truffle version command to check the installed version.
        """
        run_truffle_version()
    
    def add_truffle_config(self):
        """
        Add or update truffle config to truffle-config.js if not match or found
        """
        add_truffle_config(self.project_path, self.truffle_config)

    def get_contracts_by_project(self):
        """
        Retrieve all contracts deployed in the Truffle project.
        """
        return [Contract(**contract) for contract in get_contracts_by_project(self.ganache.rpc_url, self.project_path)]

    def get_all_accounts(self):
        """
        Retrieve all accounts from the Ganache instance using the mnemonic phrase.
        """
        return [Account(**account) for account in get_all_accounts(self.ganache.rpc_url, self.ganache.mnemonic)]
    
    def get_deployer_account(self):
        """
        Retrieve the first account from Ganache, which is typically the default account used for deployments.
        """
        return Account(**get_all_accounts(self.ganache.rpc_url, self.ganache.mnemonic)[0])
    
    def get_attacker_account(self):
        """
        Retrieve the second account from Ganache, which is typically used as an attacker account in tests.
        """
        return Account(**get_all_accounts(self.ganache.rpc_url, self.ganache.mnemonic)[1])
    
    def call_sc_function(self, from_acount: Account, contract: Contract, function_name: str, args: dict = {}):
        return call_sc_function(self.ganache.rpc_url, from_acount.address, contract.abi, contract.address, function_name, args)
    
    def get_struct_logs(self, tx_hash: str, trace_config: dict = None):
        return get_struct_logs(self.ganache.rpc_url, tx_hash, trace_config)
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize Truffle/Ganache environment.")
    parser.add_argument("--project_path", type=str, help="Path to the Truffle project", required = True)
    args = parser.parse_args()
    project_path = args.project_path

    # Example usage
    env = Env(ganache=Ganache(), project_path=project_path)
    env.init()
    
    if env.ganache.is_alive():
        log("Ganache is connected.", "success")
        contracts = env.get_contracts_by_project()
        log(f"Found {len(contracts)} contracts.", "info")
        
        accounts = env.get_all_accounts()
        log(f"Found {len(accounts)} accounts.", "info")

        log(f"Stop Ganache...")
        env.stop_ganache()
    else:
        log("Failed to connect to Ganache.", "error")