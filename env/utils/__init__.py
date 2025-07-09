import os
from .get_accounts import get_accounts
from .get_contracts import get_contracts
from .run_ganache import run_ganache
from .run_truffle_compile import run_truffle_compile
from .run_truffle_migrate import run_truffle_migrate
from .run_truflle_version import run_truffle_version
from .call_sc_function import call_sc_function
from .debug_sc_function import debug_sc_function
from .call_sc_event import call_sc_event
from .get_struct_logs import get_struct_logs
from .add_truffle_config import add_truffle_config

__all__ = [
    "get_accounts",
    "get_contracts",
    "run_ganache",
    "run_truffle_compile",
    "run_truffle_migrate",
    "run_truffle_version",
    "log",
    "is_truffle_project",
    "call_sc_function",
    "get_struct_logs",
    "add_truffle_config",
    "debug_sc_function",
    "call_sc_event"
]

def log(message, type="info"):
    """
    Simple logging function to print messages with a type.
    """
    print(f"[{type.upper()}] {message}")

def is_truffle_project(path):
    """
    Checks if the given path is a valid Truffle project.
    A valid Truffle project must contain:
      - truffle-config.js or truffle.js
      - contracts/ directory
      - migrations/ directory
    
    Args:
        path (str): The path to check for a Truffle project. 

    Returns:
        bool: True if the path is a valid Truffle project, False otherwise.
    """

    if not os.path.isdir(path):
        return False

    config_exists = (
        os.path.isfile(os.path.join(path, "truffle-config.js")) or
        os.path.isfile(os.path.join(path, "truffle.js"))
    )
    contracts_exists = os.path.isdir(os.path.join(path, "contracts"))
    migrations_exists = os.path.isdir(os.path.join(path, "migrations"))

    return config_exists and contracts_exists and migrations_exists