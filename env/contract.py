
class Contract:
    def __init__(self, name, address, creator, creation_tx, bytecode, abi):
        self.name = name
        self.address = address
        self.creator = creator
        self.creation_tx = creation_tx
        self.bytecode = bytecode
        self.abi = abi

    def __repr__(self):
        return f"Contract(address={self.address[:10]}, name={self.name}, creator={self.creator[:10]}, creation_tx={self.creation_tx[:10]})"
    
    def to_dict(self):
        return {
            "name": self.name,
            "address": self.address,
            "creator": self.creator,
            "creation_tx": self.creation_tx,
            "bytecode": self.bytecode,
            "abi": self.abi
        }
