from web3 import Web3
from ..utils import log, run_ganache

class Ganache:
    def __init__(self, mnemonic="candy maple cake sugar pudding cream honey rich smooth crumble sweet treat", rpc_url="http://127.0.1:8545"):
        """
        Initializes a Ganache instance with the given mnemonic and RPC URL.
        
        Args:
            mnemonic (str): The mnemonic phrase for account generation.
            rpc_url (str): The RPC URL for connecting to the Ganache instance.
        """
        self.mnemonic = mnemonic
        self.rpc_url = rpc_url
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.process_handler = None
    
    def is_alive(self):
        """
        Checks if the Ganache instance is running and connected.
        
        Returns:
            bool: True if connected, False otherwise.
        """
        if self.process_handler is not None and self.process_handler.poll() is not None:
            log("Ganache process is not running or stoped. Please restart it!", "error")
            self.process_handler = None
            return False
        
        if not self.w3.is_connected() and self.process_handler is None:
            log("Ganache is not running yet. Please start it first!", "INFO")
            return False

        if self.w3.is_connected() and self.process_handler is None:
            raise RuntimeError(f"Ganache is running at {self.rpc_url}, but not controllable by us. Please stop it first!")
        
        log("Ganache is running and connected.", "INFO")

        return True
    
    def start(self):
        """
        Starts a local Ganache instance using the provided mnemonic.
        If Ganache is already running, it will stop the existing instance before starting a new one.
        """
        if self.is_alive():
            self.stop()
        
        log("Starting Ganache...", "info")
        log("Ganache output will be logged to var/log/ganache.log", "info")
        self.process_handler = run_ganache(self.mnemonic, False)
    
    def stop(self):
        """
        Stops the currently running Ganache instance.
        If Ganache is not running, it will raise an error.
        """
        if not self.is_alive():
            log("Ganache is not running. Cannot stop it.", "error")
        
        log("Stopping Ganache...", "info")
        self.process_handler.kill()
        self.process_handler = None


# Add a main function for testing purposes
if __name__ == "__main__":
    ganache = Ganache()
    
    try:
        ganache.start()
        if ganache.is_alive():
            print("Ganache is running successfully.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ganache.stop()
        print("Ganache has been stopped.")