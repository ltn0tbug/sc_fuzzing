import subprocess

def run_truffle_version():
    """
    Run the Truffle version command to check the installed version of Truffle.
    This function executes the `truffle version` command and prints the output.

    Returns:
        subprocess.CompletedProcess: The result of the command execution.
    """
    # Define the Truffle version command
    command = ["truffle", "version"]

    # Run the command
    try:
        result = subprocess.run(command, check=True)
        print("Truffle version command ran successfully.")
    except subprocess.CalledProcessError as e:
        print("Failed to get Truffle version:", e)

    return result

if __name__ == "__main__":
    # Test
    run_truffle_version()