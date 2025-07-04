from web3 import Web3
import argparse
import json

def call_sc_function_function_type(w3, from_account_address, contract, fn_abi, args):
    """
    Executes a smart contract function of type 'function'. Handles both state-changing 
    and view/pure functions based on the ABI metadata.

    Args:
        w3 (Web3): Web3 instance connected to Ganache.
        from_account_address (str): Ethereum address used to send the transaction.
        contract (Contract): Contract instance.
        fn_abi (dict): ABI definition of the target function.
        args (dict): Function arguments.

    Returns:
        dict: Result of the function call with keys:
              - success (bool): Whether the call/transaction succeeded.
              - tx_hash (str or None): Transaction hash, if applicable.
              - message (str): Human-readable status message.
              - return_ (Any): Return value from call or transaction receipt.
    """
    contract_fn = getattr(contract.functions, fn_abi.get("name"))(**args)

    is_view = fn_abi.get("stateMutability") in ["view", "pure"]
    if is_view:
        return_value = contract_fn.call()
        return {
            "success": True,
            "tx_hash": None,
            "message": f"Function `{fn_abi.get('name')}` of type `view/pure` executed successfully; no transaction was created.",
            "return_": return_value
        }

    try:
        tx_hash = contract_fn.transact({"from": from_account_address})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        if receipt.status != 1:
            return {
                "success": True,
                "tx_hash": f"0x{receipt.transactionHash.hex()}",
                "message": f"Function `{fn_abi.get('name')}` executed, but transaction failed (`receipt.status=0`).",
                "return_": receipt
            }

        return {
            "success": True,
            "tx_hash": f"0x{receipt.transactionHash.hex()}",
            "message": f"Function `{fn_abi.get('name')}` executed successfully and transaction confirmed (`receipt.status=1`).",
            "return_": receipt
        }

    except Exception as e:
        return {
            "success": False,
            "tx_hash": e.args[1]['hash'] if len(e.args) > 1 and 'hash' in e.args[1] else None,
            "message": f"Execution of function `{fn_abi.get('name')}` failed. Exception: {str(e.args[0])}",
            "return_": None
        }

def call_sc_function_event_type(w3: Web3, from_account_address: str, contract, fn_abi: dict, args: dict):
    """
    Fetches and decodes logs for a specific event from a transaction hash (if provided in args['tx_hash']),
    or scans all blocks for matching event logs otherwise.

    Args:
        w3 (Web3): Web3 instance connected to Ganache.
        from_account_address (str): The address initiating the call.
        contract: Web3 Contract instance.
        fn_abi (dict): ABI definition for the event.
        args (dict): May contain 'tx_hash' to target a specific transaction log.

    Returns:
        dict: Contains success status, decoded logs or error message.
    """

    event_obj = contract.events[fn_abi["name"]]()
    tx_hash = args.get("tx_hash", None)

    if tx_hash is not None:
        try:
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            decoded_logs = event_obj.process_receipt(receipt)
            return {
                "success": True,
                "tx_hash": tx_hash,
                "message": f"Decoded {len(decoded_logs)} log(s) from transaction `{tx_hash}` for event `{fn_abi['name']}`.",
                "return_": [log["args"] for log in decoded_logs]
            }
        except Exception as tx_err:
            return {
                    "success": False,
                    "tx_hash": args.get("tx_hash", None),
                    "message": f"Failed to get logs from tx `{tx_hash}` for event `{fn_abi['name']}`. Exception: {str(tx_err)}",
                    "return_": None
                }
        
    try:
        # Fallback: scan all blocks for matching logs
        event_signature = f"{fn_abi['name']}({','.join([inp['type'] for inp in fn_abi['inputs']])})"
        event_topic = f"0x{w3.keccak(text=event_signature).hex()}"

        logs = w3.eth.get_logs({
            "address": contract.address,
            "topics": [event_topic],
            "fromBlock": "earliest",
            "toBlock": "latest"
        })
        decoded_logs = [event_obj.process_log(log) for log in logs]

        return {
            "success": True,
            "tx_hash": None,
            "message": f"Found {len(decoded_logs)} log(s) for event `{fn_abi['name']}` in full chain scan.",
            "return_": [log["args"] for log in decoded_logs]
        }

    except Exception as e:
        return {
            "success": False,
            "tx_hash": args.get("tx_hash", None),
            "message": f"Failed to decode logs for event `{fn_abi['name']}`. Exception: {str(e)}",
            "return_": None
        }

def call_sc_function(ganache_rpc_url: str, from_account_address: str, abi: list, contract_address: str, function_name: str, args: dict = {}, function_type: str = "auto"):
    """
    Dispatches a smart contract call based on the specified function name and type.

    Connects to Ganache, locates the matching function/event in the ABI, validates inputs,
    and executes the appropriate logic based on function type.

    Args:
        ganache_rpc_url (str): URL to the Ganache JSON-RPC server.
        from_account_address (str): Address used to send transactions.
        abi (list): Contract ABI.
        contract_address (str): Ethereum address of the deployed contract.
        function_name (str): Name of the function/event to invoke.
        args (dict): Parameters to pass to the function/event.
        function_type (str): One of 'auto', 'function', or 'event'. Defaults to 'auto'.

    Returns:
        dict: Result object containing:
              - success (bool)
              - tx_hash (str or None)
              - message (str)
              - return_ (Any): Output of function call or log query.
    """
    w3 = Web3(Web3.HTTPProvider(ganache_rpc_url))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to Ganache")

    contract = w3.eth.contract(address=contract_address, abi=abi)

    # Locate the function/event definition in the ABI
    if function_type == "auto":
        fn_candidates = [
            f for f in abi if f.get("type") in ["function", "event"] and f.get("name") == function_name
        ]
    elif function_type in ["function", "event"]:
        fn_candidates = [
            f for f in abi if f.get("type") == function_type and f.get("name") == function_name
        ]
    else:
        raise ValueError(f"Function type `{function_type}` is not supported.")

    if not fn_candidates:
        return {
            "success": False,
            "tx_hash": None,
            "message": f"Function `{function_name}` not found in ABI."
        }

    if len(fn_candidates) > 1:
        print(f"Multiple candidates found for `{function_name}`. Using the first match.")

    fn_abi = fn_candidates[0]
    # param_names = [inp["name"] for inp in fn_abi["inputs"]]

    # # Validate argument presence
    # missing_args = [name for name in param_names if name not in args]
    # if missing_args:
    #     return {
    #         "success": False,
    #         "tx_hash": None,
    #         "message": f"Missing required arguments for `{function_name}`: {', '.join(missing_args)}"
    #     }

    # Dispatch call based on type
    if fn_abi.get("type") == "function":
        return call_sc_function_function_type(w3, from_account_address, contract, fn_abi, args)

    return call_sc_function_event_type(w3, from_account_address, contract, fn_abi, args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Call a smart contract function via Ganache RPC.")
    parser.add_argument("--ganache_rpc_url", required=True, help="Ganache RPC URL")
    parser.add_argument("--from_account_address", required=True, help="Sender account address")
    parser.add_argument("--abi_path", required=True, help="Path to contract ABI JSON file")
    parser.add_argument("--contract_address", required=True, help="Contract address")
    parser.add_argument("--function_name", required=True, help="Function name to call")
    parser.add_argument("--args", default="{}", help="Function arguments as JSON string (e.g., '{\"param1\": 123}' for `function`, {\"paratx_hash\": 0x123... or None} for `event` type')")
    parser.add_argument("--function_type", default="auto", help="Function type. One of 'function', 'event', or 'auto'.")

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
        function_type=args.function_type
    )
    print("Transaction result:", result)