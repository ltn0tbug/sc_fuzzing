from web3 import Web3
import argparse
import json


def call_sc_function(ganache_rpc_url, from_account_address, abi, contract_address, function_name, args={}):
    """
        Calls a smart contract function using the provided account and contract details.
        This function prepares the transaction and sends it to the Ganache instance.
        
        Args:
            from_account (Account): The account to send the transaction from.
            contract (Contract): The contract to call the function on.
            function_name (str): The name of the function to call.
            args (dict): The arguments to pass to the function. Defaults to an empty dict.
        
        Returns:
            dict: A dictionary containing the result of the function call, including:
                - success (bool): Whether the function call was successful.
                - tx_hash (str): The transaction hash if the function was called successfully.
                - message (str): A message indicating the result of the function call.
    """
    w3 = Web3(Web3.HTTPProvider(ganache_rpc_url))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to Ganache")

    contract = w3.eth.contract(address=contract_address, abi=abi)

    # Find the function in ABI
    fn_candidates = [
        f for f in abi if f.get("type") == "function" and f.get("name") == function_name
    ]
    if not fn_candidates:
        return {"success": False, "tx_hash": None, "message": f"Function `{function_name}` not found in ABI."}

    fn_abi = fn_candidates[0]
    param_names = [inp["name"] for inp in fn_abi["inputs"]]

    # Check all required arguments
    missing_args = [name for name in param_names if name not in args]
    if missing_args:
        return {"success": False, "tx_hash": None, "message": f"Missing argument(s) for `{function_name}`: {', '.join(missing_args)}"}

    contract_fn = getattr(contract.functions, function_name)(**args)

    is_view = fn_abi.get("stateMutability") in ["view", "pure"]
    if is_view:
        return_value = contract_fn.call()
        return {"success": True, "tx_hash": None, "message": f"Function `{function_name}` executed successfully, but it is a {fn_abi.get("stateMutability")} function and does not send a transaction."}
    
    try:
        tx_hash = contract_fn.transact({"from": from_account_address})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        if receipt.status != 1:
            return {"success": False, "tx_hash": f"0x{receipt.transactionHash.hex()}", "message": f"Transaction sending successfully for function `{function_name}`, but still failed somehow."}

        return {"success": True, "tx_hash": f"0x{receipt.transactionHash.hex()}", "message": f"Function `{function_name}` executed successfully."}

    except Exception as e:
        return {"success": False, "tx_hash": e.args[1]['hash'], "message": f"Exception - {str(e.args[0])}"}



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Call a smart contract function via Ganache RPC.")
    parser.add_argument("--ganache_rpc_url", required=True, help="Ganache RPC URL")
    parser.add_argument("--from_account_address", required=True, help="Sender account address")
    parser.add_argument("--abi_path", required=True, help="Path to contract ABI JSON file")
    parser.add_argument("--contract_address", required=True, help="Contract address")
    parser.add_argument("--function_name", required=True, help="Function name to call")
    parser.add_argument("--args", default="{}", help="Function arguments as JSON string (e.g., '{\"param1\": 123}')")

    args = parser.parse_args()

    with open(args.abi_path, "r") as f:
        abi = json.load(f)

    fn_args = json.loads(args.args)

    tx_hash = call_sc_function(
        ganache_rpc_url=args.ganache_rpc_url,
        from_account_address=args.from_account_address,
        abi=abi,
        contract_address=args.contract_address,
        function_name=args.function_name,
        args=fn_args
    )
    print("Transaction hash:", tx_hash)
    