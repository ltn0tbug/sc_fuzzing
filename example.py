import sys
sys.path.append(r"/home/ltn0tbug/workspace/")

from sc_fuzzing.env import Env
from sc_fuzzing.env.utils import log
from sc_fuzzing.env.blockchain import Ganache


project_path="test/data/1_smartbugs_wild"

# Example usage
## Init
print("[+] {}".format("Init"))
env = Env(Ganache(), project_path)
env.init()

print(f"{"":-^100}")

## Get all deployed contracts for current project
print("[+] {}".format("Get all deployed contracts for current project"))
env.get_contracts_by_project()
contracts = env.get_contracts_by_project()
print(f"Found {len(contracts)} contracts.")
if len(contracts) >=1:
    print(f"Last deployed contract")
    print(f"Name:           {contracts[-1].name}")
    print(f"Address:        {contracts[-1].address}")
    print(f"Creator:        {contracts[-1].creator}")
    print(f"Creation TX:    {contracts[-1].creation_tx}")
    print(f"Bytecode (truncated): {contracts[-1].bytecode.hex()[:60]}...")
    print(f"ABI (truncated): {str(contracts[-1].abi)[:60]}...")

print(f"{"":-^100}")

## Get all accounts
print("[+] {}".format("Get all accounts"))
accounts = env.get_all_accounts()
print(f"Found {len(accounts)} accounts.")
deployer = env.get_deployer_account()
print(f"SC deployer account: ", deployer.to_dict())
attacker = env.get_attacker_account()
print(f"Attacker account: ", attacker.to_dict())

### Note: In default, SC deployer will be the first account and Attacker will the second account.
assert accounts[0].address == deployer.address
assert accounts[1].address == attacker.address 

print(f"{"":-^100}")

## Call function - from attacker
print("[+] {}".format("Call function - from attacker"))
from_account = attacker
contract = contracts[-1]
function_name="pauseAllTokens"
args={"_status": True, "_notice": "Some string"}

print("Caller: ", "Attacker", f"({attacker.address})")
print(f"Call function {function_name} with args: {args}")
attacker_call_result = env.call_sc_function(from_account, contract, function_name, args)
print(f"Function call success: {attacker_call_result["success"]}")
print(f"Transaction Hash: {attacker_call_result['tx_hash'] if attacker_call_result['tx_hash'] is not None else None}")
print(f"Message: {attacker_call_result['message']}")

print(f"{"":-^100}")

## Call function - from deployer (owner)
print("[+] {}".format("Call function - from deployer (owner)"))
from_account = deployer

print("Caller: ", "Deployer (owner)", f"({deployer.address})")
print(f"Call function {function_name} with args: {args}")
deployer_call_result = env.call_sc_function(from_account, contract, function_name, args)
print(f"Function call success: {deployer_call_result["success"]}")
print(f"Transaction Hash: {deployer_call_result['tx_hash'] if deployer_call_result['tx_hash'] is not None else None}")
print(f"Message: {deployer_call_result['message']}")

print(f"{"":-^100}")

## Get StructLogs
print("[+] {}".format("Get StructLogs"))
struct_logs = env.get_struct_logs(deployer_call_result['tx_hash'])
print("StructLogs:", f"{str(struct_logs)[:400]}...")

print(f"{"":-^100}")

## Stop ganache
print(f"Stop Ganache...")
env.stop_ganache()