import random
import os
import copy
import re

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


def normalize_argument_values(functions):
    """
    Normalize a list of Solidity function arguments into values that conform to their types.
    This is useful for fuzz testing and automatic input generation.

    Parameters:
        functions (List[Dict]): List of function metadata, where each function contains
        a list of arguments and their associated types and raw values.

    Returns:
        List[Dict]: The same structure, but with values converted to normalized types.
    """

    int_special_cases = {"2^256 - 1": 2**256 - 1}
    addr_special_cases = {"0x0": "0x0000000000000000000000000000000000000000"}

    def is_valid_address(addr):
        return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", addr))

    def normalize_address(val):
        if val in addr_special_cases.keys():
            return addr_special_cases[val]
        if isinstance(val, str) and is_valid_address(val):
            return val.lower()
        return "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

    def parse_bool(val):
        try:
            val_lower = str(val).strip().lower()
            if val_lower in ("true", "1"):
                return True
            if val_lower in ("false", "0"):
                return False
        except:
            pass
        return random.choice([True, False])

    def parse_int(val, signed=True):
        try:
            if val in int_special_cases:
                return int_special_cases[val]
            val = (
                str(val)
                .lower()
                .replace(" ", "")
                .replace("^", "**")
                .replace("ether", "")
                .replace("wei", "")
            )
            num = int(eval(val))
            return num if signed else max(0, num)
        except:
            if signed:
                return random.randint(-(2**255), 2**255 - 1)
            return random.randint(0, 2**256 - 1)

    def parse_bytes(val, size=None):
        try:
            if isinstance(val, bytes):
                hex_str = val.hex()
            elif isinstance(val, str) and val.startswith("0x"):
                hex_str = val[2:]
            else:
                raise ValueError()
            if not re.fullmatch(r"[a-fA-F0-9]*", hex_str):
                raise ValueError()
            if size:
                hex_str = hex_str.ljust(size * 2, "0")[: size * 2]
            elif len(hex_str) > 64:
                hex_str = hex_str[:64]
            return "0x" + hex_str.lower()
        except:
            return "0x" + os.urandom(size or 32).hex()

    def parse_string(val):
        try:
            return str(val)
        except:
            return "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

    def parse_array(val_list, subtype):
        if not isinstance(val_list, list):
            val_list = [val_list]
        return [parse_value(v, subtype) for v in val_list]

    def parse_value(val, solidity_type):
        if solidity_type.endswith("[]"):
            subtype = solidity_type[:-2]
            return parse_array(val, subtype)
        elif solidity_type.startswith("uint"):
            return parse_int(val, signed=False)
        elif solidity_type.startswith("int"):
            return parse_int(val, signed=True)
        elif solidity_type == "bool":
            return parse_bool(val)
        elif solidity_type in ("address", "address payable"):
            return normalize_address(val)
        elif solidity_type == "bytes":
            return parse_bytes(val)
        elif solidity_type == "string":
            return parse_string(val)
        elif re.fullmatch(r"bytes\d{1,2}", solidity_type):
            size = int(solidity_type[5:])
            return parse_bytes(val, size=size)

    results = copy.deepcopy(functions)

    for i, function in enumerate(functions):
        arguments = function["arguments"]
        for j, arg in enumerate(arguments):
            arg_type = arg["type"]
            if arg_type not in VALID_SOLIDITY_TYPES:
                raise ValueError(f"Unsupported Solidity type: {arg_type}")
            results[i]["arguments"][j]["values"] = [
                parse_value(v, arg_type) for v in arg["values"]
            ]
    return results
