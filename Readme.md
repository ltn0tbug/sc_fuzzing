# Smart Contract Fuzzing Environment

A Python-based environment for testing and fuzzing smart contracts using Ganache. This project supports interaction with deployed contracts, simulates attacks, and retrieves execution traces for further analysis.

## 🔧 Project Status

- ENV: **Under Construction**
- LLM: **TBD**
- RL: **TBD**

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
npm install -g ganache@7.9.2 truffle@5.11.5
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
contracts = env.get_contracts()
print(f"Found {len(contracts)} contracts.")
contract = contracts[-1]
print(f"Name:           {contracts[-1].name}")
print(f"Address:        {contracts[-1].address}")
print(f"Creator:        {contracts[-1].creator}")
print(f"Creation TX:    {contracts[-1].creation_tx}")
print(f"ABI (truncated): {str(contracts[-1].abi)[:120]}...")

""" Example Output
Found 1 contracts.
Found 1 contracts.
Name:           GlobalPause
Address:        0x8CdaF0CD259887258Bc13a92C0a6dA92698644C0
Creator:        0x627306090abaB3A6e1400e9345bC60c78a8BEf57
Creation TX:    0x7137893f541f1fe9d1e7697bd97b050cdd67ba044226136d5fc2b69447fd3510
ABI (truncated): [{'constant': True, 'inputs': [], 'name': 'pauseNotice', 'outputs': [{'name': '', 'type': 'string'}], 'payable': False, ...
----------------------------------------------------------------------------------------------------
"""
```

### 3. Get Accounts

```python
accounts = env.get_accounts()
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

### 4. Debug Function Call
> **Note**: Ganache does **not** support the `debug_traceCall` RPC method. Therefore, to obtain execution traces (`structLogs`) for any function call—including *non-state-changing* ones—this `debug_sc_function` method uses `eth_sendTransaction` to submit the transaction for any function calls and retrieve a `tx_hash`. The `tx_hash` is then used with `debug_traceTransaction` to extract the execution trace.

```python
args = {"_status": True, "_notice": "Some string"}
result = env.debug_sc_function(attacker, contract, "pauseAllTokens", args)

print(f"Success: {result["success"]}")
print(f"Transaction Hash: {result['tx_hash']}")
print(f"StructLogs: {str(result['struct_logs'])[:400]}")

""" Example Output
Success: True
Transaction Hash: 0x46eb1405405dc5c0056b1ef0ba5612fcde2ed3ae10767e399c96236955419559
StructLogs: [{'depth': 1, 'error': '', 'gas': '0x10aa0', 'gasCost': 3, 'memory': [], 'op': 'PUSH1', 'pc': 0, 'stack': [], 'storage': {}}, {'depth': 1, 'error': '', 'gas': '0x10a9d', 'gasCost': 3, 'memory': [], 'op': 'PUSH1', 'pc': 2, 'stack': ['0000000000000000000000000000000000000000000000000000000000000080'], 'storage': {}}, {'depth': 1, 'error': '', 'gas': '0x10a9a', 'gasCost': 12, 'memory': ['000000000000..
"""
```

### 5. Stop Ganache

```python
env.stop_ganache()
```

---

### 6. Other Examples

- [Example 1](example1.py): Oneshot version for the above example.
- [Example 8](example8.py): Example usage for `call_sc_function`, `call_sc_event` and `get_struct_log` method on `8_smartbugs_wild` sample

## 📝 License

This project is licensed under the [MIT License](LICENSE).

## 🤝 Collaborators

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/ltn0tbug/">
        <img src="https://avatars.githubusercontent.com/u/71972700?v=4" width="100px;" alt="ltn0tbug"/><br />
        <sub><b>ltn0tbug</b></sub>
      </a>
      <br />
      <!-- 💻 Project Lead -->
    </td>
    <td align="center">
      <a href="https://github.com/frogin-mag">
        <img src="https://avatars.githubusercontent.com/u/101979911?v=4" width="100px;" alt="frogin-mag"/><br />
        <sub><b>frogin-mag</b></sub>
      </a>
      <br />
      <!-- ⚙️ Blockchain Integration -->
    </td>
    <td align="center">
      <a href="https://github.com/hovikhanh">
        <img src="https://avatars.githubusercontent.com/u/85947145?v=4" width="100px;" alt="ViKa_618"/><br />
        <sub><b>ViKa_618</b></sub>
      </a>
      <br />
      <!-- 🧪 Testing & Examples -->
    </td>
  </tr>
</table>
