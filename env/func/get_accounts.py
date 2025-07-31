from web3 import Web3
from eth_account import Account
import argparse


def get_accounts(ganache_rpc_url, ganache_mnemonic_phrase):
    """
    Retrieve all accounts from a local Ganache instance using a mnemonic phrase.

    Connects to the specified Ganache RPC endpoint, derives each account using the provided mnemonic and standard derivation paths, and gathers account details.

    Args:
        ganache_rpc_url (str): The HTTP RPC URL of the Ganache instance.
        ganache_mnemonic_phrase (str): The mnemonic phrase used to generate Ganache accounts.

    Returns:
        list: A list of dictionaries, each containing:
            - address (str): The account address.
            - private_key (HexBytes): The account's private key.
            - balance_wei (int): Account balance in Wei.
    """

    # Enable HD wallet features in eth-account
    Account.enable_unaudited_hdwallet_features()

    w3 = Web3(Web3.HTTPProvider(ganache_rpc_url))

    # Check if connected to Ganache
    if not w3.is_connected():
        raise Exception("Failed to connect to Ganache")

    # Get all accounts from Ganache
    accounts = w3.eth.accounts

    accounts_info = []

    for i, account in enumerate(accounts):

        # Derivation path for Ganache account ith
        derivation_path = f"m/44'/60'/0'/0/{i}"

        # Derive account
        derive_account = Account.from_mnemonic(
            ganache_mnemonic_phrase, account_path=derivation_path
        )

        assert (
            derive_account.address == account
        ), f"Address mismatch ({derive_account.address} != {account}). Please check the mnemonic or derivation path."

        # Save account info
        accounts_info.append(
            {
                "address": account,
                "private_key": derive_account.key,
            }
        )

    return accounts_info


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Retrieve all Ganache accounts using mnemonic and RPC URL."
    )
    parser.add_argument(
        "--mnemonic",
        type=str,
        help="Ganache mnemonic phrase",
        default="candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
    )
    parser.add_argument(
        "--rpc-url", type=str, help="Ganache RPC URL", default="http://127.0.0.1:8545"
    )

    args = parser.parse_args()

    ganache_mnemonic_phrase = args.mnemonic
    ganache_rpc_url = args.rpc_url

    print("Retrieving all accounts from Ganache...")
    print(f"Using mnemonic: {ganache_mnemonic_phrase}")
    print(f"Using RPC URL: {ganache_rpc_url}")
    w3 = Web3(Web3.HTTPProvider(ganache_rpc_url))
    accounts = get_accounts(ganache_rpc_url, ganache_mnemonic_phrase)
    # Print all accounts info
    for i, a in enumerate(accounts):
        print(f"\nAccount {i + 1}")  # Print account details
        print(f"Account Address: {a['address']}")
        print(f"Private Key: {a['private_key'].to_0x_hex()}")
        print(f"Balance (Wei): {a['balance']:,}")
        print(
            f"Balance (ETH): {Web3.from_wei(w3.eth.get_balance(a['address']), 'ether'):,}"
        )
        print(f"Nonce: {w3.eth.get_transaction_count(a['address'])}")

    print("\nAll accounts info retrieved successfully.")
