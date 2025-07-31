import os


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

    config_exists = os.path.isfile(
        os.path.join(path, "truffle-config.js")
    ) or os.path.isfile(os.path.join(path, "truffle.js"))
    contracts_exists = os.path.isdir(os.path.join(path, "contracts"))
    migrations_exists = os.path.isdir(os.path.join(path, "migrations"))

    return config_exists and contracts_exists and migrations_exists
