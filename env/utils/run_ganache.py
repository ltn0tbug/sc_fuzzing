import subprocess
import os
import argparse

def run_ganache(ganache_mnemonic, log_to_console=False):
    """
    Launch ganache-cli using the provided mnemonic.

    Args:
        ganache_mnemonic (str): The mnemonic phrase for account generation.
        log_to_console (bool): If True, logs are printed to the console; otherwise, logs are written to var/log/ganache.log.

    Returns:
        subprocess.Popen: The process object for the running ganache-cli instance.
    """
    command = [
        "ganache",
        "-m",
        ganache_mnemonic,
        "-e",
        "1000000000", # 1_000_000_000 ETH
        "--logging.debug",
        "--logging.verbose"
    ]
    if log_to_console:
        process = subprocess.Popen(command)
        print("Ganache started. Press Ctrl+C to stop.")
        try:
            process.communicate()
        except KeyboardInterrupt:
            process.terminate()
            print("Ganache stopped.")
    else:
        os.makedirs("var/log", exist_ok=True)
        log_file = open("var/log/ganache.log", "w")
        process = subprocess.Popen(command, stdout=log_file, stderr=log_file)
    return process

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Ganache with a specified mnemonic.")
    parser.add_argument(
        "--mnemonic",
        type=str,
        default="candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
        help="Mnemonic phrase for Ganache account generation."
    )
    parser.add_argument(
        "--log-to-console",
        action="store_true",
        help="If set, logs are printed to the console."
    )
    args = parser.parse_args()
    mnemonic = args.mnemonic
    log_to_console = args.log_to_console
    run_ganache(mnemonic, log_to_console)
    if args.log_to_console:
        print("Ganache is running in background mode. Please check the log in var/log/ganache.log")