from web3 import Web3
import json
import argparse


def get_struct_logs(ganache_rpc_url: str, tx_hash: str, trace_config: dict = None):
    """
    Retrieve struct logs for a specific transaction from a Ganache instance.
    Connects to the specified Ganache RPC endpoint and uses the `debug_traceTransaction` method to get detailed execution logs.

    Args:
        ganache_rpc_url (str): The HTTP RPC URL of the Ganache instance.
        tx_hash (str): The transaction hash to trace. Expected to be in hexadecimal format (e.g., "0x123...").
        trace_config (dict, optional): Configuration for tracing options. If None, Geth’s Default configuration is used (e.g., enable memory, stack, and storage tracing).
    
    Returns:
        list: A list of struct logs for the transaction, each containing:
            - pc (int): Program counter.
            - op (str): The opcode executed.
            - gas (int): Remaining gas after the operation.
            - gasCost (int): Gas cost of the operation.
            - depth (int): Call stack depth.
            - stack (list): Stack at this point in execution.
            - memory (list): Memory at this point in execution.
            - storage (dict): Storage changes made by this operation.
            - error (str, optional): Error message if the operation failed.
    """

    w3 = Web3(Web3.HTTPProvider(ganache_rpc_url))
    # Verify connection


    # Prepare trace config (optional, reduces output)
    if trace_config is None:
        # Geth’s default configuration
        trace_config = {
            "disableMemory": False,
            "disableStack": False,
            "disableStorage": False,
            "enableReturnData": False,
            "tracer": "",
            "timeout": ""
        }

    # Make the raw JSON-RPC call to debug_traceTransaction
    response = w3.provider.make_request(
        method="debug_traceTransaction",
        params=[tx_hash, trace_config]
    )

    # Handle response
    if "error" in response:
        print("Error:", response["error"])
    else:
        trace = response["result"]

    return trace.get("structLogs", [])


# main function for testing
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Get struct logs for a transaction from Ganache.")
    parser.add_argument("--ganache_rpc_url", required=True, help="Ganache RPC URL")
    parser.add_argument("--tx_hash", required=True, help="Transaction hash to trace")
    parser.add_argument("--trace_config", type=json.loads, default=None, help="Trace configuration as JSON string (e.g., '{\"disableMemory\": true, \"disableStack\": true, \"disableStorage\": true}')")
    

    args = parser.parse_args()

    struct_logs = get_struct_logs(args.ganache_rpc_url, args.tx_hash, args.trace_config)

    print(json.dumps(struct_logs, indent=2))