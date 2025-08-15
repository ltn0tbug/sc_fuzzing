from web3 import Web3
import logging

logger = logging.getLogger(__name__)


class Contract:
    def __init__(
        self, name, address, creator, creation_tx, abi, rpc_url="http://127.0.1:8545"
    ):
        self.name = name
        self.address = address
        self.creator = creator
        self.creation_tx = creation_tx
        self.abi = abi
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.balance = self.get_balance()

    def __repr__(self):
        return (
            f"Contract(address={self.address}, name={self.name}, creator={self.creator}, creation_tx={self.creation_tx}, balance={self.balance:,} Wei)"
            if self.w3.is_connected()
            else f"Contract(address={self.address}, name={self.name}, creator={self.creator}, creation_tx={self.creation_tx}, balance=Unknown)"
        )

    def is_connected(self):
        """
        Check if the Web3 instance is connected to the Ethereum node.
        """
        if self.w3.is_connected():
            return True
        logger.error(
            f"Failed to connect to the Ethereum node. Please check the RPC URL. ({self.rpc_url})"
        )
        return False

    def get_balance(self):
        """
        Get the balance of the account in Wei.
        """
        return self.w3.eth.get_balance(self.address) if self.is_connected() else None

    def to_dict(self):
        return {
            "name": self.name,
            "address": self.address,
            "creator": self.creator,
            "creation_tx": self.creation_tx,
            "abi": self.abi,
        }
