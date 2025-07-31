from web3 import Web3
import argparse
import json


def call_sc_event(
    ganache_rpc_url: str,
    abi: list,
    contract_address: str,
    event_name: str,
    tx_hash: str = None
):
    """
    Fetch and decode logs for a specified smart contract event, optionally from a given transaction hash.
    Falls back to scanning the entire blockchain if no tx_hash is provided.

    Parameters:
    - ganache_rpc_url (str): HTTP RPC URL of the Ganache node.
    - abi (list): The ABI of the smart contract.
    - contract_address (str): The deployed contract's address.
    - event_name (str): The name of the event to search for.
    - tx_hash (str, optional): The transaction hash to decode logs from. If None, scan all blocks.

    Returns:
    dict: {
        "success": bool,
        "tx_hash": str or None,
        "return_": list of event arguments or None
    }
    """

    w3 = Web3(Web3.HTTPProvider(ganache_rpc_url))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to Ganache")

    contract = w3.eth.contract(address=contract_address, abi=abi)

    # Locate the event definition in the ABI
    event_candidates = [
        item for item in abi
        if item.get("type") == "event" and item.get("name") == event_name
    ]

    if len(event_candidates) > 1:
        raise ValueError(f"Multiple candidates found for `{event_name}`: {event_candidates}")

    if len(event_candidates) == 0:
        raise ValueError(f"Could not find `{event_name}` in contract ABI.")

    event_abi = event_candidates[0]
    event_obj = contract.events[event_abi["name"]]()

    # If a specific transaction is provided, extract logs from its receipt
    if tx_hash is not None:
        try:
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            decoded_logs = event_obj.process_receipt(receipt)
            return {
                "success": True,
                "tx_hash": tx_hash,
                "return_": [log["args"] for log in decoded_logs]
            }
        except Exception as tx_err:
            print(f"Exception while processing transaction receipt: {tx_err}")
            return {
                "success": False,
                "tx_hash": tx_hash,
                "return_": None
            }

    # Fallback: search all blocks for matching logs
    try:
        # Generate the event signature and keccak topic
        event_signature = f"{event_abi['name']}({','.join([inp['type'] for inp in event_abi['inputs']])})"
        event_topic = w3.keccak(text=event_signature).to_0x_hex()

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
            "return_": [log["args"] for log in decoded_logs]
        }

    except Exception as e:
        print(f"Exception while scanning logs: {e}")
        return {
            "success": False,
            "tx_hash": None,
            "return_": None
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch and decode logs for a smart contract event on Ganache.")
    parser.add_argument("--ganache_rpc_url", required=True, help="Ganache RPC URL")
    parser.add_argument("--abi_path", required=True, help="Path to contract ABI JSON file")
    parser.add_argument("--contract_address", required=True, help="Contract address")
    parser.add_argument("--event_name", required=True, help="Event name to fetch")
    parser.add_argument("--tx_hash", default=None, help="Optional transaction hash to decode logs from")

    args = parser.parse_args()

    # Load ABI from file
    with open(args.abi_path, "r") as f:
        abi = json.load(f)

    # Call the event parser function
    result = call_sc_event(
        ganache_rpc_url=args.ganache_rpc_url,
        abi=abi,
        contract_address=args.contract_address,
        event_name=args.event_name,
        tx_hash=args.tx_hash
    )

    # Output result
    print("📦 Event Log Result:")
    print(json.dumps(result, indent=2))