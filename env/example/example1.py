# if you did not install `sc_fuzzing` in PYTHONPATH, the below line is required.
if __name__ == "__main__":
    from pathlib import Path
    import sys
    sys.path.append(Path(__file__).parent.parent.parent.parent.as_posix())

from sc_fuzzing.env import Env
from sc_fuzzing.env.blockchain import Ganache
from sc_fuzzing.data.dataloader import DataLoader

# Example usage

# Get sampe data from DataLoader
sbc_metadata_df = DataLoader().get_metadata("smartbugs_curated")
sample = sbc_metadata_df[sbc_metadata_df["name"] == "erc20"].iloc[0]

## Init
print("[+] {}".format("Init"))

project_path = sample["project_path"]
env = Env(Ganache(), project_path)
env.init()

print(f"{"":-^100}")

## Get all deployed contracts for current project
print("[+] {}".format("Get all deployed contracts for current project"))
contracts = env.get_contracts()
print(f"Found {len(contracts)} contracts.")
primary_contracts = [contract for contract in contracts if contract.name == sample["primary_contract"]]
if len(primary_contracts) == 0:
    raise ValueError(f"Primary contract '{sample['name']}' not found in the environment.")
contract = primary_contracts[0]
print(f"Name:           {contract.name}")
print(f"Address:        {contract.address}")
print(f"Creator:        {contract.creator}")
print(f"Creation TX:    {contract.creation_tx}")
print(f"ABI (truncated): {str(contract.abi)[:120]}...")

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

function_name = "transfer"
args = {"to": attacker.address, "value": 10*6}
result = env.debug_sc_function(deployer, contract, function_name, args)

print(f"Success: {result["success"]}")
print(f"Transaction Hash: {result['tx_hash']}")
print(f"StructLogs: {str(result['struct_logs'])[:400]}")

print(f"{"":-^100}")

## Stop ganache
print(f"Stop Ganache...")
env.stop_ganache()