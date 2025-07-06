
class Contract:
    def __init__(self, name, address, creator, creation_tx, abi):
        self.name = name
        self.address = address
        self.creator = creator
        self.creation_tx = creation_tx
        self.abi = abi

    def __repr__(self):
        return f"Contract(address={self.address}, name={self.name}, creator={self.creator}, creation_tx={self.creation_tx})"
    
    def to_dict(self):
        return {
            "name": self.name,
            "address": self.address,
            "creator": self.creator,
            "creation_tx": self.creation_tx,
            "abi": self.abi
        }
