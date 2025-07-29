from web3 import Web3
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def parse_dict(ganache_arg : dict):
    arg_template = r"--{}.{}"
    command = []
    for arg, sub_args in ganache_arg.items():
        if arg not in ["server", "wallet", "miner", "logging", "chain", "database"]:
            raise ValueError(f"The specified Ganache {arg} argument does not exist or is not supported.")
        for sub_arg, value in sub_args.items():
            if isinstance(value, bool):
                if value == True:
                    command.append(arg_template.format(arg,sub_arg))
            else:
                command.append(arg_template.format(arg,sub_arg))
                command.append(str(value))
    
    return command


def run_ganache(ganache_arg: dict|list = None, log_to_file: bool = False, log_file_path: str = None):
    """
    Launch ganache-cli using the provided mnemonic.

    Args:
        ganache_mnemonic (str): The mnemonic phrase for account generation.
        log_to_console (bool): If True, logs are printed to the console; otherwise, logs are written to var/log/ganache.log.

    Returns:
        subprocess.Popen: The process object for the running ganache-cli instance.
    """
    if isinstance(ganache_arg, list):
        command = ["ganache"] + ganache_arg 
    elif isinstance(ganache_arg, dict):
        command = ["ganache"] + parse_dict(ganache_arg)
    else:
        command = [
            "ganache",
            "-m",
            "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
            "-e",
            "1000000000", # 1_000_000_000 ETH
            "--logging.debug",
            "--logging.verbose"
        ]
    if log_to_file == False:
        process = subprocess.Popen(command)
        logger.info("Ganache started. Press Ctrl+C to stop.")
        try:
            process.communicate()
        except KeyboardInterrupt:
            process.terminate()
            logger.info("Ganache stopped.")
    else:
        path = Path(log_file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        log_file_handler = open(path, "a")
        process = subprocess.Popen(command, stdout=log_file_handler, stderr=log_file_handler)
        logger.info(f"Ganache started. Logs are being written to {log_file_path}.")
    return process

class Ganache:
    def __init__(self, config: dict = None):
        """
        Initializes a Ganache instance with the given mnemonic and RPC URL.
        
        Args:
            mnemonic (str): The mnemonic phrase for account generation.
            rpc_url (str): The RPC URL for connecting to the Ganache instance.
        """
        self.config = config
        self.rpc_url = "http://127.0.0.1:8545" if config is None else f"http://{config['server']['host']}:{config['server']['port']}"
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.process_handler = None
    
    def is_running(self):
        """
        Checks if the Ganache instance is running and connected.
        
        Returns:
            bool: True if connected, False otherwise.
        """
        if self.process_handler is not None and self.process_handler.poll() is not None:
            logger.warning("Ganache process is not running or stoped, but not by us.")
            return False
        
        if not self.w3.is_connected() and self.process_handler is None:
            return False

        if self.w3.is_connected() and (self.process_handler is None or self.process_handler.poll() is not None):
            logger.warning(f"Ganache is running at {self.rpc_url} but not managed by this instance.")
            return True
        return True
    
    def start(self, log_to_file = False, log_file_path = None):
        """
        Starts a local Ganache instance using the provided mnemonic.
        If Ganache is already running, it will stop the existing instance before starting a new one.
        """
        if self.is_running():
            logger.warning("Ganache is already running. Stopping the existing instance...")
            if self.stop() == False:
                return False
        
        logger.info("Starting Ganache...")
        self.process_handler = run_ganache(self.config, log_to_file, log_file_path)
        return True
    
    def stop(self):
        """
        Stops the currently running Ganache instance.
        If Ganache is not running, it will raise an error.
        """
        if self.process_handler is not None and self.process_handler.poll() is not None:
            logger.warning("Ganache process is not running or stoped, but not by us.")
            return False     
        if not self.w3.is_connected() and self.process_handler is None:
            logger.error("Ganache is not running. Cannot stop it.")
            return False
        if self.w3.is_connected() and (self.process_handler is None or self.process_handler.poll() is not None):
            logger.error(f"Ganache is running at {self.rpc_url} but not managed by this instance. Can not stop it.")
            return False

        logger.info("Stopping Ganache...")
        self.process_handler.kill()
        self.process_handler = None
        return True


# Add a main function for testing purposes
if __name__ == "__main__":
    ganache = Ganache()
    
    try:
        ganache.start()
        if ganache.is_running():
            print("Ganache is running successfully.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ganache.stop()
        print("Ganache has been stopped.")