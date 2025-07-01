import sys
sys.path.append(r"/home/ltn0tbug/workspace/")

from sc_fuzzing.env.utils import (
    get_all_accounts,
    get_contracts_by_project,
    run_ganache,
    run_truffle_compile,
    run_truffle_migrate,
    call_sc_function,
    get_struct_logs
)



mnemonic = "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat"
ganache_rpc_url = "http://127.0.0.1:8545"
log_to_console = False
project_path = "test/data/1_smartbugs_wild"

print("Start Ganache.")
process = run_ganache(mnemonic, log_to_console)

print(f"Compiling Truffle project at {project_path}...")
run_truffle_compile(project_path)
print(f"Migrating Truffle project at {project_path}...")
run_truffle_migrate(project_path)


accounts = get_all_accounts(ganache_rpc_url, mnemonic)

contracts = get_contracts_by_project(ganache_rpc_url, project_path)

from_account_address = accounts[0]['address']
abi = contracts[-1]['abi']
contract_address = contracts[-1]['address']
function_name="pauseAllTokens"

args={"_status": True, "_notice": "Some string"}
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
latest_block = w3.eth.get_block('latest', full_transactions=True)

if latest_block.transactions:
    last_tx = latest_block.transactions[-1]  # Last transaction in block
    print("Current latest tx_hash:", f"0x{last_tx.hash.hex()}" if last_tx.hash is not None else None)
else:
    print("No transactions found in the latest block.")

print(f"Call function {function_name} with args: {args}")
result = call_sc_function(ganache_rpc_url, from_account_address, abi, contract_address, function_name, args)

print(f"Function call success: {result["success"]}")
print(f"Transaction hash: {result['tx_hash'] if result['tx_hash'] is not None else None}")
# print(f"Return value: {result['return_']}")
print(f"Message: {result['message']}")

latest_block = w3.eth.get_block('latest', full_transactions=True)

if latest_block.transactions:
    last_tx = latest_block.transactions[-1]  # Last transaction in block
    print("Current latest tx_hash:", result['tx_hash']if result['tx_hash'] is not None else None)
else:
    print("No transactions found in the latest block.")

if result['tx_hash'] is not None:

    struct_logs = get_struct_logs(ganache_rpc_url, result['tx_hash'])
    print(struct_logs)


print("Stop Ganache.")
process.kill()