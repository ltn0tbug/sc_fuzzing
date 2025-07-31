import subprocess
import argparse
import logging
from pathlib import Path


logger = logging.getLogger(__name__)


def run_truffle_compile(
    project_path: str, log_to_file: bool = False, log_file_path: str = None
):
    """
    Launch Truffle to compile the smart contracts in the specified project directory.

    Args:
        project_path (str): The path to the Truffle project directory.

    Returns:
        subprocess.CompletedProcess: The result of the compilation command.
    """
    # Define the Truffle compile command
    command = ["truffle", "compile", "--all"]

    # Run the command
    try:
        if log_to_file == False:
            result = subprocess.run(command, check=True, cwd=project_path)
            logging.info("Compile completed with exit code:", result.returncode)

        path = Path(log_file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        log_file_handler = open(path, "a")
        result = subprocess.run(
            command,
            stdout=log_file_handler,
            stderr=log_file_handler,
            check=True,
            cwd=project_path,
        )
        logger.info(
            f"Compile completed with exit code: {result.returncode}. Command outputs are being written to {path}."
        )
        return result

    except subprocess.CalledProcessError as e:
        logging.error(f"Compile failed with error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compile a Truffle project.")
    parser.add_argument(
        "project_path",
        nargs="?",
        required=True,
        help="Path to the Truffle project directory.",
    )
    args = parser.parse_args()

    project_path = args.project_path

    # Run the Truffle compile command
    print(f"Compiling Truffle project at {project_path}...")
    run_truffle_compile(project_path)
