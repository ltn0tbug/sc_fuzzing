import json
import ctypes

from ..ethereum import ContractManager, AccountManager
from .logger import Logger
from ..ethereum import Method


import os
import json
import hashlib
from evmdasm import EvmBytecode


def method_id(signature):
    return hashlib.sha3_256(signature.encode()).hexdigest()[:8]


def parse_abi(abi_json):
    constructor = {
        "Name": "constructor",
        "ID": None,
        "Const": False,
        "Inputs": [],
        "Outputs": []
    }

    methods = {}
    payable = {}

    for item in abi_json:
        if item["type"] == "constructor":
            constructor["Inputs"] = item.get("inputs", [])
        elif item["type"] == "function":
            name = item["name"]
            inputs = item.get("inputs", [])
            input_sig = ",".join([i["type"] for i in inputs])
            sig = f"{name}({input_sig})"
            methods[name] = {
                "Name": name,
                "ID": method_id(sig),
                "Const": item.get("stateMutability") in ("view", "pure"),
                "Inputs": inputs,
                "Outputs": item.get("outputs", [])
            }
            payable[name] = item.get("stateMutability") == "payable"
    return constructor, methods, payable


def disassemble(bytecode_hex):
    if bytecode_hex.startswith("0x"):
        bytecode_hex = bytecode_hex[2:]
    bytecode = bytes.fromhex(bytecode_hex)
    disasm = EvmBytecode(bytecode).disassemble()
    return [
        {
            "pc": int(insn.address),
            "op": insn.name,
            "arg": getattr(insn, "operand", None)
        }
        for insn in disasm
    ]


def load_contract_data(env_contracts, proj_path):
    """
    env_contracts: list of contracts from get_contracts() call (name, address, creator, abi json, etc.)
    proj_path: root path to your project (contains build/contracts)
    """
    contracts_dir = os.path.join(proj_path, "build", "contracts")
    result = {}

    for c in env_contracts:
        print(c)
        name = c.name
        json_path = os.path.join(contracts_dir, f"{name}.json")

        if not os.path.exists(json_path):
            print(f"[!] JSON not found for {name}")
            continue

        with open(json_path) as f:
            compiled = json.load(f)

        abi_json = compiled.get("abi", [])
        bytecode = compiled.get("deployedBytecode", "")

        constructor, methods, payable = parse_abi(abi_json)
        insns = disassemble(bytecode)

        result[name] = {
            "name": name,
            "addresses": [c.address],
            "payable": payable,
            "abi": {
                "Constructor": constructor,
                "Methods": methods
            },
            "insns": insns
        }

    return result

class Execution:

    def __init__(self, path, env):
        
        self.env = env
        self.path = path


    def set_backend(self, proj_path):
        """
        initialize the ethereum backend
        """
        proj_path = proj_path.encode('ascii')
        bs = self.lib.SetBackend(proj_path)
        j = json.loads(bs.decode())
        loggers = [Logger(**l) for l in j] # the fuzzLogger
        return loggers


    def get_contracts(self):
        contracts = self.env.get_contracts() 
        bs = load_contract_data(contracts, self.path)
        j = json.loads(bs.decode())
        return ContractManager(**j)


    def get_accounts(self):
        def load_account_manager(env):
            raw_accounts = env.get_accounts()
            deployer = env.get_deployer_account()
            attacker = env.get_attacker_account()

            attacker_addr = attacker.address if hasattr(attacker, "address") else attacker["address"]

            accounts_data = []
            for acc in raw_accounts:
                addr = acc.address if hasattr(acc, "address") else acc["address"]
                balance = acc.balance if hasattr(acc, "balance") else acc["balance"]
                accounts_data.append({
                    "address": addr,
                    "amount": int(balance),
                    "is_attacker": addr == attacker_addr
                })

            return accounts_data
        bs = load_account_manager(self.env)
        j = json.loads(bs.decode())
        manager = AccountManager(**j)
        return manager


    def commit_tx(self, tx):
        if tx.method == Method.FALLBACK:
            tx.method = ''
        tx = tx.to_execution_str().encode('ascii')
        bs = self.lib.CommitTx(tx)
        j = json.loads(bs.decode())
        # print(j)
        logger = Logger(**j)
        if logger.tx.method == '':
            logger.tx.method = Method.FALLBACK
        return logger


    def jump_state(self, state_id):
        self.lib.JumpState(state_id)


    def set_balance(self, address, amount):
        params = {
            'address': str(address),
            'amount': str(amount),
        }
        params = json.dumps(params).encode('ascii')
        self.lib.SetBalance(params)