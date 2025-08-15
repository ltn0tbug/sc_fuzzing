import re
import argparse
import os
import logging

logger = logging.getLogger(__name__)


def remove_truffle_config(project_path: str):
    """
    Removes the fuzzing config block from the Truffle config file.
    """
    truffle_config_path = None

    for config_file in ["truffle-config.js", "truffle.js"]:
        potential_path = os.path.join(project_path, config_file)
        if os.path.isfile(potential_path):
            truffle_config_path = potential_path
            break

    if truffle_config_path is None:
        raise ValueError(f"No Truffle configuration file found in {project_path}.")

    with open(truffle_config_path, "r") as file:
        content = file.read()

    # Regex to match the full block from BEGIN to END
    pattern = r"/\*---BEGIN-FUZZING-CONFIG---.*?---END-FUZZING-CONFIG---\*/"
    new_content, count = re.subn(pattern, "", content, flags=re.DOTALL)

    if count > 0:
        with open(truffle_config_path, "w") as file:
            file.write(new_content.strip() + "\n")
        logger.info("Fuzzing config block removed from Truffle config.")
    else:
        logger.info("No fuzzing config block found to remove.")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Add or update fuzzing config in truffle-config.js"
    )
    parser.add_argument(
        "--path", type=str, required=True, help="Path to truffle project directory."
    )

    args = parser.parse_args()

    remove_truffle_config(truffle_config_path=args.path)
