import subprocess
import argparse

def run_truffle_migrate(project_path, network="fuzzing", log_to_console = False):
    """
    Launch Truffle to migrate the smart contracts in the specified project directory.

    Args:
        project_path (str): The path to the Truffle project directory.
        
    Returns:
        subprocess.CompletedProcess: The result of the migration command.
    """
    # Define the Truffle migrate command
    
    command = ["truffle", "migrate", "--network", network]

    # Run the command
    try:
        result = subprocess.run(command, check=True, cwd=project_path)
        print("Migration completed with exit code:", result.returncode)
        return result
    except subprocess.CalledProcessError as e:
        print("Migration failed with error:", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate a Truffle project.")
    parser.add_argument(
        "project_path",
        nargs="?",
        required=True,
        help="Path to the Truffle project directory.",
    )
    args = parser.parse_args()

    project_path = args.project_path

    # Run the Truffle migrate command
    print(f"Migrating Truffle project at {project_path}...")
    run_truffle_migrate(project_path)