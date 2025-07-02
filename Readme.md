# Smart Contract Fuzzing Environment

A Python-based environment for testing and fuzzing smart contracts using Ganache. This project supports interaction with deployed contracts, simulates attacks, and retrieves execution traces for further analysis.

## 🔧 Project Status

- ENV: **Under Construction**
- LLM: **TBD**
- RF: **TBD**

## 📁 Project Structure

- `sc_fuzzing/env/`: Core environment utilities
- `sc_fuzzing/env/blockchain.py`: Ganache integration
- `sc_fuzzing/test/data/`: Sample smart contract projects

## 📦 Requirements

### Python 3.8+

```bash
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

### node 17+

```bash
npm install -g npm-packages.json
```

## 🚀 Example Usage for ENV

## 0. Package Setup

```python
# (Optional) if you work outside the module root
# import sys
# sys.path.append(r"/path/to/workspace/")

from sc_fuzzing.env import Env
from sc_fuzzing.env.blockchain import Ganache
```

### 1. Initialize Environment

```python
project_path = "sc-fuzzing/test/data/1_smartbugs_wild"
env = Env(Ganache(), project_path)
env.init()

""" Example Output
[INFO] Initializing environment...
[INFO] Initializing Ganache...
[INFO] Ganache is not running yet. Please start it first!
[INFO] Ganache is not running yet. Please start it first!
[INFO] Starting Ganache...
[INFO] Ganache output will be logged to var/log/ganache.log
[INFO] Update Truffle configuration...
Fuzzing block found and matches the expected configuration.
[INFO] Running Truffle compile...
...
"""
```

### 2. Get Deployed Contracts & View Lastest Deployed Contract Info

```python
contracts = env.get_contracts_by_project()
print(f"Found {len(contracts)} contracts.")
contract = contracts[-1]
print(f"Name:           {contracts[-1].name}")
print(f"Address:        {contracts[-1].address}")
print(f"Creator:        {contracts[-1].creator}")
print(f"Creation TX:    {contracts[-1].creation_tx}")
print(f"Bytecode (truncated): {contracts[-1].bytecode.hex()[:60]}...")
print(f"ABI (truncated): {str(contracts[-1].abi)[:60]}...")

""" Example Output
Found 1 contracts.
Name:           GlobalPause
Address:        0x8CdaF0CD259887258Bc13a92C0a6dA92698644C0
Creator:        0x627306090abaB3A6e1400e9345bC60c78a8BEf57
Creation TX:    0x7137893f541f1fe9d1e7697bd97b050cdd67ba044226136d5fc2b69447fd3510
Bytecode (truncated): 60806040526004361061008e576000357c01000000000000000000000000...
ABI (truncated): [{'constant': True, 'inputs': [], 'name': 'pauseNotice', 'ou...
"""
```

### 3. Get Accounts

```python
accounts = env.get_all_accounts()
deployer = env.get_deployer_account()
attacker = env.get_attacker_account()
# In default setting, deployer will be the first account and attacker will the second account.
assert accounts[0].address == deployer.address
assert accounts[1].address == attacker.address
print(f"Attacker account: ", attacker.to_dict())

""" Example Output
Attacker account:  {'address': '0xf17f52151EbEF6C7334FAD080c5704D77216b732', 'private_key': HexBytes('0xae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f'), 'balance': 1000000000000000000000, 'nonce': 0}
"""
```

### 4. Call Function as Attacker

```python
args = {"_status": True, "_notice": "Some string"}
result = env.call_sc_function(attacker, contract, "pauseAllTokens", args)
print("Success:", result["success"])
print(f"Transaction Hash: {result['tx_hash'] if result['tx_hash'] is not None else None}")
print(f"Message: {result['message']}")

""" Example Output
Caller:  Attacker (0xf17f52151EbEF6C7334FAD080c5704D77216b732)
Call function pauseAllTokens with args: {'_status': True, '_notice': 'Some string'}
Success: False
Transaction Hash: None
Message: Exception - execution reverted: VM Exception while processing transaction: revert
"""
```

### 5. Call Function as Deployer

```python
result = env.call_sc_function(deployer, contract, "pauseAllTokens", args)
print("Success:", result["success"])
print("Success:", result["success"])
print(f"Transaction Hash: {result['tx_hash'] if result['tx_hash'] is not None else None}")
print(f"Message: {result['message']}")

""" Example Output
Caller:  Deployer (owner) (0x627306090abaB3A6e1400e9345bC60c78a8BEf57)
Call function pauseAllTokens with args: {'_status': True, '_notice': 'Some string'}
Success: True
Transaction Hash: 0x814bf6b44a9d54ba1f0f6588de2cec0342a6de5fe4d55d50cce28526599b7579
Message: Function `pauseAllTokens` executed successfully
"""
```



### 6. Get Execution Trace (StructLogs)

```python
logs = env.get_struct_logs(result["tx_hash"])
print("StructLogs:", logs[:400])

""" Example Output
StructLogs: [{'depth': 1, 'error': '', 'gas': '0x23f7b', 'gasCost': 3, 'memory': [], 'op': 'PUSH1', 'pc': 0, 'stack': [], 'storage': {}}, {'depth': 1, 'error': '', 'gas': '0x23f78', 'gasCost': 3, 'memory': [], 'op': 'PUSH1', 'pc': 2, 'stack': ['0000000000000000000000000000000000000000000000000000000000000080'], 'storage': {}}, {'depth': 1, 'error': '', 'gas': '0x23f75', 'gasCost': 12, 'memory': ['000000000000...
"""
```

### 7. Stop Ganache

```python
env.stop_ganache()
```

## 🧪 Testing

Tested with sample smart contracts in the `test/data` project directory.

---

## 📝 License

This project is licensed under the MIT License.

