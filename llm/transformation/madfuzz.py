import random
import os
import copy
import re

# Basic
VALID_SOLIDITY_TYPES = ["uint", "int", "bool", "address", "bytes", "string"]

VALID_SOLIDITY_TYPES += [f"uint{x}" for x in range(8, 257, 8)]
VALID_SOLIDITY_TYPES += [f"int{x}" for x in range(8, 257, 8)]
VALID_SOLIDITY_TYPES += [f"bytes{x}" for x in range(1, 33)]


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
            if signed:
                return (
                    num
                    if num >= -(2**255) and num <= 2**255 - 1
                    else random.randint(-(2**255), 2**255 - 1)
                )
            return (
                num if num >= 0 and num <= 2**256 - 1 else random.randint(0, 2**256 - 1)
            )
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
            return bytes.fromhex(hex_str.lower())
        except:
            return os.urandom(size or 32)

    def parse_string(val):
        try:
            return str(val)
        except:
            return "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

    def parse_array(val_list, subtype, size=None):
        if not isinstance(val_list, list):
            val_list = [val_list]

        if size is None or (size is not None and len(val_list) == size):
            return [parse_value(v, subtype) for v in val_list]

        if len(val_list) > size:
            return [
                parse_value(v, subtype) for v in val_list[: -(len(val_list) - size)]
            ]

        raise ValueError(f"Length not match {val_list} < {size}")

    def parse_value(val, solidity_type):
        if solidity_type.endswith("[]"):
            subtype = solidity_type[:-2]
            return parse_array(val, subtype)
        elif re.fullmatch(r"(.+)\[(\d+)\]", solidity_type):
            match = re.fullmatch(r"(.+)\[(\d+)\]", solidity_type)
            subtype, size = match.groups()
            return parse_array(val, subtype, int(size))
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
                match = re.fullmatch(r"([a-zA-Z0-9_]+)((\[\d*\])*)", arg_type)
                if match:
                    subtype = match.groups()[0]
                    if subtype not in VALID_SOLIDITY_TYPES:
                        raise ValueError(f"Unsupported Solidity type: {arg_type}")
                else:
                    raise ValueError(f"Unsupported Solidity type: {arg_type}")

            results[i]["arguments"][j]["values"] = [
                parse_value(v, arg_type) for v in arg["values"]
            ]
    return results
