# Smart Contract Fuzzing Environment

A Python-based environment for testing and fuzzing smart contracts using Ganache. This project supports interaction with deployed contracts, simulates attacks, and retrieves execution traces for further analysis.

## 🚀 Example Usage for ENV

## 0. Package Setup

```python
from sc_fuzzing.env import Env
from sc_fuzzing.env.blockchain import Ganache
from sc_fuzzing.data.dataloader import DataLoader
```

### 1. Get sample
```python
sbc_metadata_df = DataLoader().get_metadata("smartbugs_curated")
sample = sbc_metadata_df[sbc_metadata_df["name"] == "erc20"].iloc[0]
sample

""" Example Output
name                                                            erc20
project_path        /home/ltn0tbug/workspace/sc_fuzzing/data/smart...
primary_contract                                                ERC20
compiler_version                                               0.4.24
label                                                   front_running
Name: 46, dtype: object
``` 

### 2. Initialize Environment

```python
project_path = sample["project_path"]
env = Env(Ganache(), project_path)
env.init()

""" Example Output
[INFO] Initializing environment...
[INFO] Initializing Ganache...
[INFO] Ganache is not running yet. Please start it first!
[INFO] Starting Ganache...
[INFO] Ganache output will be logged to var/log/ganache.log
[INFO] Update Truffle configuration...
Fuzzing block found and matches the expected configuration.
[INFO] Running Truffle compile...
...
"""
```

### 3. Get Deployed Contracts & View Primary Contract Info

```python
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

""" Example Output
Found 1 contracts.
Name:           ERC20
Address:        0x8CdaF0CD259887258Bc13a92C0a6dA92698644C0
Creator:        0x627306090abaB3A6e1400e9345bC60c78a8BEf57
Creation TX:    0x743b7ff9b0f5a0b2b000c2fd53f6612b0c5adf1777a7ae0b88e4c3038e408005
ABI (truncated): [{'inputs': [{'name': 'totalSupply', 'type': 'uint256'}], 'payable': False, 'stateMutability': 'nonpayable', 'type': 'co...
"""
```

### 3. Get Accounts

```python
accounts = env.get_accounts()
print(f"Found {len(accounts)} accounts.")
deployer = env.get_deployer_account()
print(f"SC deployer account: ", deployer.to_dict())
attacker = env.get_attacker_account()
print(f"Attacker account: ", attacker.to_dict())

### Note: In default, SC deployer will be the first account and Attacker will the second account.
assert accounts[0].address == deployer.address
assert accounts[1].address == attacker.address 

""" Example Output
Found 10 accounts.
SC deployer account:  {'address': '0x627306090abaB3A6e1400e9345bC60c78a8BEf57', 'private_key': HexBytes('0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3'), 'balance': 999997719013000000000, 'nonce': 1}
Attacker account:  {'address': '0xf17f52151EbEF6C7334FAD080c5704D77216b732', 'private_key': HexBytes('0xae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f'), 'balance': 1000000000000000000000, 'nonce': 0}
"""
```

### 4. Debug Function Call
> **Note**: Ganache does **not** support the `debug_traceCall` RPC method. Therefore, to obtain execution traces (`structLogs`) for any function call—including *non-state-changing* ones—this `debug_sc_function` method uses `eth_sendTransaction` to submit the transaction for any function calls and retrieve a `tx_hash`. The `tx_hash` is then used with `debug_traceTransaction` to extract the execution trace.

```python
function_name = "transfer"
args = {"to": attacker.address, "value": 10*6}
result = env.debug_sc_function(deployer, contract, function_name, args)

print(f"Success: {result["success"]}")
print(f"Transaction Hash: {result['tx_hash']}")
print(f"StructLogs: {str(result['struct_logs'])[:400]}...")

""" Example Output
Success: True
Transaction Hash: 0xad024400ea7936503c0258378e5001f6366b32ea6cda3590a952e1f917e5617b
StructLogs: [{'depth': 1, 'error': '', 'gas': '0x10b4c', 'gasCost': 3, 'memory': [], 'op': 'PUSH1', 'pc': 0, 'stack': [], 'storage': {}}, {'depth': 1, 'error': '', 'gas': '0x10b49', 'gasCost': 3, 'memory': [], 'op': 'PUSH1', 'pc': 2, 'stack': ['0000000000000000000000000000000000000000000000000000000000000080'], 'storage': {}}, {'depth': 1, 'error': '', 'gas': '0x10b46', 'gasCost': 12, 'memory': ['000000000000...
"""
```

### 5. Stop Ganache

```python
env.stop_ganache()
```

---

### 6. Other Examples

- [Example 1](example1.py): Oneshot version for the above example.
- [Example 2](example2.py): Example usage for `call_sc_function`, `call_sc_event` and `get_struct_log` method on `ERC20` sample
