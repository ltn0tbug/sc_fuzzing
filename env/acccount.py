from web3 import Web3

class Account:
    def __init__(self, address, private_key, rpc_url="http://127.0.1:8545"):
        self.address = address
        self.private_key = private_key
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.rpc_url = rpc_url

    def __repr__(self):

        return f"Account(address={self.address}, balance={self.get_account_balance():,} Wei, nonce={self.get_account_nonce()})" if self.w3.is_connected() else f"Account(address={self.address}, balance=Unknown, nonce=Unknown)"
    
    def is_connected(self):
        """
        Check if the Web3 instance is connected to the Ethereum node.
        """
        if self.w3.is_connected():
            return True
        print(f"Failed to connect to the Ethereum node. Please check the RPC URL. ({self.rpc_url})")
        return False
    
    def get_balance(self):
        """
        Get the balance of the account in Wei.
        """
        return self.w3.eth.get_balance(self.address) if self.is_connected() else None
    
    def set_balance(self, balance: int):
        """
        Set the balance of the account (for testing purposes).
        """
        if not self.is_connected():
            raise Exception(f"Web3 is not connected. Cannot set balance. Please check the RPC URL. ({self.rpc_url})")
        return self.w3.provider.make_request("evm_setAccountBalance", [self.address, balance])

    def get_nonce(self):
        """
        Get the nonce of the account.
        """
        return self.w3.eth.get_transaction_count(self.address) if self.is_connected() else None

    def to_dict(self):
        return {
            "address": self.address,
            "private_key": self.private_key,
            "balance": self.get_balance(),
            "nonce": self.get_nonce()
        }