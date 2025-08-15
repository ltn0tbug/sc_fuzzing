import re
import argparse
import json
import os
import logging

logger = logging.getLogger(__name__)

START_CONFIG_TEMPLATE = """/*---BEGIN-FUZZING-CONFIG---*/
const config = module.exports;
"""

END_CONFIG_TEMPLATE = """
// Export the modified configuration
module.exports = config;
/*---END-FUZZING-CONFIG---*/"""

NETWORK_TEMPLATE = """
// Modify the configuration to add a new network for fuzzing
config.networks = config.networks || {{}};
config.networks.{name} = {{
    host: "{host}",
    port: {port},
    network_id: "{network_id}", // Match any network id
}}
"""

OPTIMIZER_TEMPLATE = """
// Modify the configuration to add a new compilers setting for fuzzing
config.compilers = config.compilers || {{}};
config.compilers.solc = config.compilers.solc || {{}};
config.compilers.solc.settings = config.compilers.solc.settings || {{}};
config.compilers.solc.settings.optimizer = {{
    enabled: {enabled},
    runs: {runs},
}}
"""


def add_truffle_config(project_path: str, config: dict = None):

    if config is None:
        config = {
            "network": {
                "name": "fuzzing",
                "host": "127.0.0.1",
                "port": 8545,
                "network_id": "*",
            }
        }
    addon_config = START_CONFIG_TEMPLATE

    if config.get("network"):
        addon_config += NETWORK_TEMPLATE.format(**config["network"])

    if config.get("optimizer"):
        config["optimizer"]["enabled"] = (
            "true" if config["optimizer"]["enabled"] else "false"
        )
        addon_config += OPTIMIZER_TEMPLATE.format(**config["optimizer"])

    addon_config += END_CONFIG_TEMPLATE

    # Generate the addon configuration
    # addon_config = TEMPLATE.format(**config["network"])

    truffle_config_path = None

    for config_file in ["truffle-config.js", "truffle.js"]:
        if os.path.isfile(os.path.join(project_path, config_file)):
            truffle_config_path = os.path.join(project_path, config_file)
            break

    if truffle_config_path is None:
        raise ValueError(
            f"Error: No Truffle configuration file existed in {project_path}."
        )

    with open(truffle_config_path, "r") as file:
        content = file.read()

    pattern = r"/\*---BEGIN-FUZZING-CONFIG---.+---END-FUZZING-CONFIG---\*/"
    match = re.search(pattern, content, re.DOTALL)

    if match:
        block = match.group(0)
        if block == addon_config:
            logger.info("Fuzzing block found and matches the expected configuration.")
        else:
            new_content = re.sub(pattern, addon_config, content, flags=re.DOTALL)
            with open(truffle_config_path, "w") as file:
                file.write(new_content)
            logger.info(
                "Fuzzing block found but did not match. Updated the configuration."
            )
    else:
        new_content = content + "\n" * 3 + addon_config
        with open(truffle_config_path, "w") as file:
            file.write(new_content)
        logger.info("Fuzzing block not found. Added the configuration to the file.")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Add or update fuzzing config in truffle-config.js"
    )
    parser.add_argument(
        "--path", type=str, required=True, help="Path to truffle project directory."
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help='JSON string of the config to add (e.g. \'{"name": "fuzzing", "host": "127.0.01", "port": 8545, "network_id": "*"}\').',
    )

    args = parser.parse_args()
    config = (
        json.loads(args.config)
        if args.config
        else {"name": "fuzzing", "host": "127.0.0.1", "port": 8545, "network_id": "*"}
    )

    add_truffle_config(truffle_config_path=args.path, config=config)
