from .utils import *
from .blockchain import Ganache
from .acccount import Account
from .contract import Contract
from ..utils import GLOBAL_CONFIG, GLOBAL_LOG_PATH, get_config
import argparse
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class Env:
    def __init__(self, ganache: Ganache, project_path: str, config: str|dict = None):
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
    
        if config is None:
            self.config = GLOBAL_CONFIG
        elif isinstance(config, str):
            self.config = get_config(config)
        else:
            self.config = config

        self.log_path = self.config.get('log_path', GLOBAL_LOG_PATH)
        ganache.__init__(self.config['ganache'])
        self.ganache = ganache
        self.rpc_url = ganache.rpc_url


    def init(self):
        """
        Initializes the Truffle/Ganache environment by starting Ganache, compiling the Truffle project,
        and migrating the contracts to the local Ganache instance.
        """

        # Init Ganache
        logger.info("Initializing environment...")
        logger.info("Initializing Ganache...")
        if self.start_ganache(self.config.get('force_stop', False), True, Path(self.log_path, "ganache.log")) == False:
            logger.error("Failed to start Ganache.")
            return False
        
        # Init Truffle
        logger.info("Update Truffle configuration...")
        self.add_truffle_config(self.config['truffle'])
        logger.info("Running Truffle compile...")
        self.run_truffle_compile(True, Path(self.log_path, "truffle_compile.log"))
        logger.info("Running Truffle migrate...")
        self.run_truffle_migrate(self.config['truffle']['network']['name'], True, Path(self.log_path, "truffle_migrate.log"))
    
    def start_ganache(self, force_stop=False,  log_to_file=False, log_file_path=None):
        return self.ganache.start(force_stop, log_to_file, log_file_path)
    
    def stop_ganache(self):
        return self.ganache.stop(self.config.get('force_stop', False))

    def run_truffle_compile(self, log_to_file=False, log_file_path=None):
        """
        Runs the Truffle compile command to compile the smart contracts in the project.
        """
        run_truffle_compile(self.project_path, log_to_file, log_file_path)

    def run_truffle_migrate(self, network="fuzzing", log_to_file=False, log_file_path=None):
        """
        Runs the Truffle migrate command to deploy the compiled contracts to the local Ganache instance.
        """
        run_truffle_migrate(self.project_path, network, log_to_file, log_file_path)

    def run_truffle_version(self):
        """
        Runs the Truffle version command to check the installed version.
        """
        run_truffle_version()
    
    def add_truffle_config(self, truffle_config : dict = None):
        """
        Add or update truffle config to truffle-config.js if not match or found
        """
        add_truffle_config(self.project_path, truffle_config)

    def get_contracts(self):
        """
        Retrieve all contracts deployed in the Truffle project.
        """
        return [Contract(**contract) for contract in get_contracts(self.rpc_url, self.project_path)]

    def get_accounts(self):
        """
        Retrieve all accounts from the Ganache instance using the mnemonic phrase.
        """
        return [Account(rpc_url=self.rpc_url, **account) for account in get_accounts(self.rpc_url, self.config['ganache']['wallet']['mnemonic'])]
    
    def get_deployer_account(self):
        """
        Retrieve the first account from Ganache, which is typically the default account used for deployments.
        """
        return Account(rpc_url=self.rpc_url, **get_accounts(self.rpc_url, self.config['ganache']['wallet']['mnemonic'])[0])
    
    def get_attacker_account(self):
        """
        Retrieve the second account from Ganache, which is typically used as an attacker account in tests.
        """
        return Account(rpc_url=self.rpc_url, **get_accounts(self.rpc_url, self.config['ganache']['wallet']['mnemonic'])[1])
    
    def call_sc_function(self, from_acount: Account, contract: Contract, function_name: str, args: dict = {}):
        return call_sc_function(self.rpc_url, from_acount.address, contract.abi, contract.address, function_name, args)
    
    def call_sc_event(self, contract: Contract, event_name: str, tx_hash: str = None):
        return call_sc_event(self.rpc_url, contract.abi, contract.address, event_name, tx_hash)
    
    def debug_sc_function(self, from_acount: Account, contract: Contract, function_name: str, args: dict = {}):
        return debug_sc_function(self.rpc_url, from_acount.address, contract.abi, contract.address, function_name, args)
    
    def get_struct_logs(self, tx_hash: str, trace_config: dict = None):
        return get_struct_logs(self.rpc_url, tx_hash, trace_config)
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize Truffle/Ganache environment.")
    parser.add_argument("--project_path", type=str, help="Path to the Truffle project", required = True)
    args = parser.parse_args()
    project_path = args.project_path

    # Example usage
    env = Env(ganache=Ganache(), project_path=project_path)
    env.init()
    
    if env.ganache.is_alive():
        print("Ganache is connected.")
        contracts = env.get_contracts()
        print(f"Found {len(contracts)} contracts.")
        
        accounts = env.get_accounts()
        print(f"Found {len(accounts)} accounts.")

        print(f"Stop Ganache...")
        env.stop_ganache()
    else:
        print("Failed to connect to Ganache.", "error")