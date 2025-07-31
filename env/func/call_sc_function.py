from web3 import Web3
import argparse
import json

from web3 import Web3


def call_sc_function(
    ganache_rpc_url: str,
    from_account_address: str,
    abi: list,
    contract_address: str,
    function_name: str,
    args: dict = {},
):
    """
    Call a smart contract function deployed on a Ganache node.

    Args:
        ganache_rpc_url (str): The HTTP RPC URL of the Ganache node.
        from_account_address (str): Address initiating the transaction.
        abi (list): The contract ABI.
        contract_address (str): The deployed contract address.
        function_name (str): The name of the function to call.
        args (dict): A dictionary of arguments to pass to the function.

    Returns:
        dict: {
            "success": bool,
            "tx_hash": str or None,
            "return_": result or receipt or None
        }
    """

    # Connect to Ganache
    w3 = Web3(Web3.HTTPProvider(ganache_rpc_url))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to Ganache")

    # Instantiate contract object
    contract = w3.eth.contract(address=contract_address, abi=abi)

    # Find function candidates in ABI matching name and number of inputs
    fn_candidates = [
        f
        for f in abi
        if f.get("type") == "function"
        and f.get("name") == function_name
        and len(f.get("inputs", [])) == len(args)
    ]

    # Handle ambiguity
    if len(fn_candidates) > 1:
        raise ValueError(
            f"Multiple candidates found for `{function_name}`: {fn_candidates}"
        )

    # Handle missing function
    if len(fn_candidates) == 0:
        raise ValueError(f"Could not find `{function_name}` in contract ABI.")

    # Use the first matching ABI definition
    fn_abi = fn_candidates[0]

    # Ensure all expected named arguments are provided
    param_names = [inp["name"] for inp in fn_abi["inputs"]]
    missing_args = [name for name in param_names if name not in args]
    if missing_args:
        raise ValueError(
            f"Missing required arguments for `{function_name}`: {', '.join(missing_args)}"
        )

    # Create a contract function object with arguments
    contract_fn = getattr(contract.functions, function_name)(**args)

    try:
        # Check if function is view or pure (does not modify state)
        is_view = fn_abi.get("stateMutability") in ["view", "pure"]
        if is_view:
            return_value = contract_fn.call()
            return {"success": True, "tx_hash": None, "return_": return_value}

        # Otherwise, send transaction and wait for receipt
        tx_hash = contract_fn.transact({"from": from_account_address})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        return {
            "success": True,
            "tx_hash": receipt.transactionHash.to_0x_hex(),
            "return_": receipt,
        }

    except Exception as e:
        print(f"Exception occurred during contract function call: {e}")
        return {"success": False, "tx_hash": None, "return_": None}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Call a smart contract function via Ganache RPC."
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
        help='Function arguments as JSON string (e.g., \'{"param1": 123}\' for `function`, {"paratx_hash": 0x123... or None} for `event` type\')',
    )
    parser.add_argument(
        "--function_type",
        default="auto",
        help="Function type. One of 'function', 'event', or 'auto'.",
    )

    args = parser.parse_args()

    with open(args.abi_path, "r") as f:
        abi = json.load(f)

    fn_args = json.loads(args.args)

    result = call_sc_function(
        ganache_rpc_url=args.ganache_rpc_url,
        from_account_address=args.from_account_address,
        abi=abi,
        contract_address=args.contract_address,
        function_name=args.function_name,
        args=fn_args,
        function_type=args.function_type,
    )
    print("Transaction result:", result)
