import sys
sys.path.append(r"/home/ltn0tbug/workspace/")

from sc_fuzzing.env import Env
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

## Debug function
print("[+] {}".format("Debug function (call function - alway return tx_hash, even for view/pure function and get StructLogs)"))

contract = contracts[-1]
function_name="pauseAllTokens"
args={"_status": True, "_notice": "Some string"}

print("Caller: ", "Attacker", f"({attacker.address})")
print(f"Debug function {function_name} with args: {args}")
result = env.debug_sc_function(attacker, contract, function_name, args)
print(f"Success: {result["success"]}")
print(f"Transaction Hash: {result['tx_hash']}")
print(f"StructLogs: {str(result['struct_logs'])[:400]}...")

print(f"{"":-^100}")

## Stop ganache
print(f"Stop Ganache...")
env.stop_ganache()