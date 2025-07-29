import subprocess
import argparse

def run_truffle_compile(project_path, log_to_console = False):
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
        result = subprocess.run(command, check=True, cwd=project_path)
        print("Compile completed with exit code:", result.returncode)
        return result
    except subprocess.CalledProcessError as e:
        print("Compile failed with error:", e)

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