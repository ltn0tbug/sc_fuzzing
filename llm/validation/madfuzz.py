import json
import logging
import re


# Set up logger
logger = logging.getLogger(__name__)

VALID_SOLIDITY_TYPES = set(
    [
        # Integer types
        "uint",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "uint128",
        "uint256",
        "int",
        "int8",
        "int16",
        "int32",
        "int64",
        "int128",
        "int256",
        # Other value types
        "bool",
        "address",
        "address payable",
        "bytes",
        "string",
        # Arrays
        "uint[]",
        "int[]",
        "bool[]",
        "address[]",
        "string[]",
        "bytes[]",
    ]
    + [f"bytes{i}" for i in range(1, 33)]
)  # Adds bytes1 to bytes32


def is_madfuzz_json(json_string: str) -> bool:
    """
    Validates if a JSON string conforms to the expected function-arguments format
    required by MadFuzz. Logs errors and returns True/False.

    Returns:
        bool: True if valid, False if invalid.
    """
    try:
        data = json.loads(json_string)
    except json.JSONDecodeError as e:
        logger.error(
            f"Invalid JSON format: {e.msg} at line {e.lineno} column {e.colno}"
        )
        return False

    if not isinstance(data, list):
        logger.error("Top-level JSON must be a list")
        return False

    for i, func in enumerate(data):
        if not isinstance(func, dict):
            logger.error(f"Item at index {i} is not an object")
            return False

        if "function_name" not in func or not isinstance(func["function_name"], str):
            logger.error(f"Missing or invalid 'function_name' at index {i}")
            return False

        if "arguments" not in func or not isinstance(func["arguments"], list):
            logger.error(f"Missing or invalid 'arguments' list at index {i}")
            return False

        if len(func["arguments"]) == 0:
            continue

        for j, arg in enumerate(func["arguments"]):
            if not isinstance(arg, dict):
                logger.error(
                    f"Argument at index {j} in function '{func['function_name']}' is not an object"
                )
                return False

            for key in ["name", "type", "values"]:
                if key not in arg:
                    logger.error(
                        f"Missing '{key}' in argument {j} of function '{func['function_name']}'"
                    )
                    return False

            if (
                not isinstance(arg["name"], str)
                or not isinstance(arg["type"], str)
                or not isinstance(arg["values"], list)
            ):
                logger.error(
                    f"Invalid types in argument {j} of function '{func['function_name']}'"
                )
                return False

            # ✅ Validate Solidity type
            if arg["type"] not in VALID_SOLIDITY_TYPES:
                logger.error(
                    f"Unsupported Solidity type '{arg['type']}' in argument {j} of function '{func['function_name']}'"
                )
                return False

    return True
