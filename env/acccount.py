
class Account:
    def __init__(self, address, private_key, balance, nonce):
        self.address = address
        self.private_key = private_key
        self.balance = balance
        self.nonce = nonce

    def __repr__(self):
        return f"Account(address={self.address}, balance={self.balance:,} Wei)"
    
    def to_dict(self):
        return {
            "address": self.address,
            "private_key": self.private_key,
            "balance": self.balance,
            "nonce": self.nonce
        }