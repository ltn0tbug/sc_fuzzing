from web3 import Web3
import subprocess
import logging
from pathlib import Path
import sys
import os

logger = logging.getLogger(__name__)


def parse_dict(ganache_args: dict):
    arg_template = r"--{}.{}"
    command = []
    for arg, sub_args in ganache_args.items():
        if arg not in ["server", "wallet", "miner", "logging", "chain", "database"]:
            raise ValueError(
                f"The specified Ganache {arg} argument does not exist or is not supported."
            )
        for sub_arg, value in sub_args.items():
            if isinstance(value, bool):
                if value == True:
                    command.append(arg_template.format(arg, sub_arg))
            else:
                command.append(arg_template.format(arg, sub_arg))
                command.append(str(value))

    return command


def run_ganache(
    ganache_args: dict | list = None,
    log_to_file: bool = False,
    log_file_path: str = None,
):
    """
    Starts a ganache-cli instance with the specifiedlogging configuration.

    Args:
       ganache_args (dict|list): A dictionary of ganache-cli arguments or a list of arguments
       log_to_file (bool): If True, logs will be written to a file. If False, logs will be printed to the console.
       log_file_path (str): The path to the log file. If None, the log file will be created in the current directory.

    Returns:
        subprocess.Popen: The process object for the running ganache-cli instance.
    """
    if isinstance(ganache_args, list):
        command = ["ganache"] + ganache_args
    elif isinstance(ganache_args, dict):
        command = ["ganache"] + parse_dict(ganache_args)
    else:
        command = [
            "ganache",
            "-m",
            "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
            "-e",
            "1000000000",  # 1_000_000_000 ETH
            "--logging.debug",
            "--logging.verbose",
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
        process = subprocess.Popen(
            command, stdout=log_file_handler, stderr=log_file_handler
        )
        logger.info(f"Ganache started. Logs are being written to {log_file_path}.")
    return process


def force_stop_process_by_port(port: int) -> bool:
    """
    Forcefully kills the process using the given port.

    Args:
        port (int): The port number to check.

    Returns:
        bool: True if a process was killed, False otherwise.
    """
    try:
        if sys.platform.startswith("win"):
            # Windows
            result = subprocess.check_output(
                f"netstat -ano | findstr LISTENING | findstr :{port}",
                shell=True,
                text=True,
            )
            pids = set()
            for line in result.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 5:
                    pids.add(parts[-1])
            if not pids:
                logger.error("No process found using port {port}")
                return False
            for pid in pids:
                subprocess.run(
                    f"taskkill /PID {pid} /F",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                logger.info("Killed process {pid} using port {port}")
            return True
        else:
            # Linux/macOS: use lsof + grep for LISTEN
            result = subprocess.check_output(
                f"lsof -nP -iTCP:{port} -sTCP:LISTEN -t", shell=True, text=True
            )
            pids = result.strip().split()
            if not pids:
                logger.error("No process found using port {port}")
                return False
            for pid in pids:
                os.kill(int(pid), 9)  # SIGKILL
                logger.info("Killed process {pid} using port {port}")
            return True
    except Exception as e:
        logger.error(f"Exception occurred while killing process on port {port}: {e}")
        return False  # Error occurred


class Ganache:
    def __init__(self, config: dict = None):
        """
        Initializes a Ganache instance with the given mnemonic and RPC URL.

        Args:
            mnemonic (str): The mnemonic phrase for account generation.
            rpc_url (str): The RPC URL for connecting to the Ganache instance.
        """
        self.config = config
        self.rpc_url = (
            "http://127.0.0.1:8545"
            if config is None
            else f"http://{config['server']['host']}:{config['server']['port']}"
        )
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

        if self.w3.is_connected() and (
            self.process_handler is None or self.process_handler.poll() is not None
        ):
            logger.warning(
                f"Ganache is running at {self.rpc_url} but not managed by this instance."
            )
            return True
        return True

    def start(self, force_stop=False, log_to_file=False, log_file_path=None):
        """
        Starts a local Ganache instance with the specified configuration.
        If Ganache is already running, it will stop the existing instance before starting a new one.
        """
        if self.is_running():
            logger.warning(
                "Ganache is already running. Stopping the existing instance..."
            )
            if self.stop(force_stop) == False:
                return False

        logger.info("Starting Ganache...")
        self.process_handler = run_ganache(self.config, log_to_file, log_file_path)
        return True

    def stop(self, force_stop=False):
        """
        Stops the currently running Ganache instance.
        If Ganache is not running, it will log a warning and return `False`
        """
        if self.process_handler is not None and self.process_handler.poll() is not None:
            logger.warning("Ganache process is not running or stoped, but not by us.")
            return False
        if not self.w3.is_connected() and self.process_handler is None:
            logger.error("Ganache is not running. Cannot stop it.")
            return False
        if self.w3.is_connected() and (
            self.process_handler is None or self.process_handler.poll() is not None
        ):
            if force_stop:
                logger.info(
                    f"Trying to force stop Ganache by killing all process using port {self.config['server']['port']}..."
                )
                return force_stop_process_by_port(self.config["server"]["port"])
            logger.error(
                f"Ganache is running at {self.rpc_url} but not managed by this instance. Can not stop it."
            )
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
