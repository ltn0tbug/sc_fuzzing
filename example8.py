import sys
sys.path.append(r"/home/ltn0tbug/workspace/")

from sc_fuzzing.env import Env
from sc_fuzzing.env.utils import log
from sc_fuzzing.env.blockchain import Ganache


project_path="test/data/8_smartbugs_wild"

# Example usage
## Init
print("[+] {}".format("Init"))
env = Env(Ganache(), project_path)
env.init()

print(f"{"":-^100}")

## Get all deployed contracts for current project
print("[+] {}".format("Get all deployed contracts for current project"))
env.get_contracts()
contracts = env.get_contracts()
print(f"Found {len(contracts)} contracts.")
if len(contracts) >=1:
    print(f"Last deployed contract")
    print(f"Name:           {contracts[-1].name}")
    print(f"Address:        {contracts[-1].address}")
    print(f"Creator:        {contracts[-1].creator}")
    print(f"Creation TX:    {contracts[-1].creation_tx}")
    print(f"ABI (truncated): {str(contracts[-1].abi)[:120]}...")

print(f"{"":-^100}")

## Get all accounts
print("[+] {}".format("Get all accounts"))
accounts = env.get_accounts()
print(f"Found {len(accounts)} accounts.")
deployer = env.get_deployer_account()
print(f"SC deployer account: ", deployer.to_dict())
attacker = env.get_attacker_account()
print(f"Attacker account: ", attacker.to_dict())

### Note: In default, SC deployer will be the first account and Attacker will the second account.
assert accounts[0].address == deployer.address
assert accounts[1].address == attacker.address 

print(f"{"":-^100}")

## Call function
print("[+] {}".format("Call function"))

contract=contracts[-1]
mint_function_name="mint"
mint_args={"value": 10}
transfer_function_name="transfer"
transfer_args={"to": attacker.address, "value": 5}
transfer_event="Transfer"


print("Caller:", "Deployer", f"({deployer.address})")
print(f"Call function {mint_function_name} with args: {mint_args}")
result = env.call_sc_function(deployer, contract, mint_function_name, mint_args)
print(f"Success: {result["success"]}")
print(f"Transaction Hash: {result['tx_hash'] if result['tx_hash'] is not None else None}")
print(f"Message: {result['message']}")
print(f"Reture_: {result['return_']}")

print("Caller:", "Deployer", f"({deployer.address})")
print(f"Call function {transfer_function_name} with args: {transfer_args}")
result = env.call_sc_function(deployer, contract, transfer_function_name, transfer_args)
print(f"Success: {result["success"]}")
print(f"Transaction Hash: {result['tx_hash'] if result['tx_hash'] is not None else None}")
print(f"Message: {result['message']}")
print(f"Reture_: {result['return_']}")

print(f"{"":-^100}")


print("[+] {}".format("Call Event"))

print("Caller: ", "Deployer", f"({deployer.address})")
print(f"Call Event {transfer_event} with args: {{}}")
result = env.call_sc_function(deployer, contract, transfer_event, {})
print(f"Success: {result["success"]}")
print(f"Transaction Hash: {result['tx_hash'] if result['tx_hash'] is not None else None}")
print(f"Message: {result['message']}")
print(f"Reture_: {result['return_']}")

print(f"{"":-^100}")

## Get StructLogs
# print("[+] {}".format("Get StructLogs"))
# struct_logs = env.get_struct_logs(deployer_call_result['tx_hash'])
# print("StructLogs:", f"{str(struct_logs)[:400]}...")

print(f"{"":-^100}")

## Stop ganache
print(f"Stop Ganache...")
env.stop_ganache()