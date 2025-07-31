from web3 import Web3
import argparse
import json
from .get_struct_logs import get_struct_logs


def debug_sc_function(
    ganache_rpc_url: str,
    from_account_address: str,
    abi: list,
    contract_address: str,
    function_name: str,
    args: dict = {},
):
    """
    Attempt to call a smart contract function on a local Ganache node and return execution trace.

    If the function is not found in the ABI, the function sends an intentionally invalid
    transaction (with invalid selector) to trigger a fallback or error for debugging purposes.

    Args:
        ganache_rpc_url (str): HTTP RPC URL of the Ganache node.
        from_account_address (str): Sender address (must be unlocked in Ganache).
        abi (list): Contract ABI.
        contract_address (str): Address of the deployed contract.
        function_name (str): Name of the function to call.
        args (dict): Named arguments for the function.

    Returns:
        dict: {
            "tx_hash": str or None,
            "struct_logs": List or None,
            "Success": bool
        }
    """

    w3 = Web3(Web3.HTTPProvider(ganache_rpc_url))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to Ganache")

    contract = w3.eth.contract(address=contract_address, abi=abi)

    # Try to find function definition in the ABI that matches name and arg count
    fn_candidates = [
        f
        for f in abi
        if f.get("type") == "function"
        and f.get("name") == function_name
        and len(f.get("inputs", [])) == len(args)
    ]

    # Handle ambiguous matches
    if len(fn_candidates) > 1:
        raise ValueError(
            f"Multiple candidates found for `{function_name}`: {fn_candidates}"
        )

    # If function not found, send invalid function call
    if len(fn_candidates) == 0:
        print(
            f"Could not find `{function_name}` in contract ABI. "
            "Transaction with invalid data (0x3d52b82c) will be sent to trigger fallback."
        )

        tx = {
            "from": from_account_address,
            "to": contract_address,
            "data": "0x3d52b82c",  # Invalid function selector (e.g. from hash of 'inteand()')
        }

        tx_response = w3.provider.make_request("eth_sendTransaction", [tx])

        if "error" in tx_response:
            print("Error:", tx_response["error"])
            return {"success": False, "tx_hash": None, "struct_logs": None}

        return {
            "success": True,
            "tx_hash": tx_response["result"],
            "struct_logs": get_struct_logs(ganache_rpc_url, tx_response["result"]),
        }

    # Function was found in ABI
    fn_abi = fn_candidates[0]

    # Validate that all required parameters are provided
    param_names = [inp["name"] for inp in fn_abi["inputs"]]
    missing_args = [name for name in param_names if name not in args]
    if missing_args:
        raise ValueError(
            f"Missing required arguments for `{function_name}`: {', '.join(missing_args)}"
        )

    # Create contract function call and encode ABI
    contract_fn = getattr(contract.functions, fn_abi.get("name"))(**args)
    fn_encoded_abi = contract.encode_abi(
        contract_fn.abi_element_identifier, kwargs=args
    )

    tx = {"from": from_account_address, "to": contract_address, "data": fn_encoded_abi}

    tx_response = w3.provider.make_request("eth_sendTransaction", [tx])

    if "error" in tx_response:
        print("Error:", tx_response["error"])
        return {"success": False, "tx_hash": None, "struct_logs": None}

    return {
        "success": True,
        "tx_hash": tx_response["result"],
        "struct_logs": get_struct_logs(ganache_rpc_url, tx_response["result"]),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Debug a smart contract function via Ganache RPC."
    )
    parser.add_argument("--ganache_rpc_url", required=True, help="Ganache RPC URL")
    parser.add_argument(
        "--from_account_address", required=True, help="Sender account address"
    )
    parser.add_argument(
        "--abi_path", required=True, help="Path to contract ABI JSON file"
    )
    parser.add_argument("--contract_address", required=True, help="Contract address")
    parser.add_argument("--function_name", required=True, help="Function name to call")
    parser.add_argument(
        "--args",
        default="{}",
        help="Function arguments as JSON string (e.g., '{\"param1\": 123}')",
    )

    args = parser.parse_args()

    # Load ABI from file
    with open(args.abi_path, "r") as f:
        abi = json.load(f)

    # Parse function arguments
    try:
        fn_args = json.loads(args.args)
    except json.JSONDecodeError:
        print("❌ Invalid JSON format in --args")
        exit(1)

    # Call the debug function
    result = debug_sc_function(
        ganache_rpc_url=args.ganache_rpc_url,
        from_account_address=args.from_account_address,
        abi=abi,
        contract_address=args.contract_address,
        function_name=args.function_name,
        args=fn_args,
    )

    print("📦 Transaction Result:")
    print(json.dumps(result, indent=2))
