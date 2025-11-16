from web3 import Web3
import json

# Connect to local Ganache
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Verify connection
if not web3.is_connected():
    raise Exception("Failed to connect to Ganache")

# Replace with your FileVault contract address
contract_address = "0x89d4bf9Daf68103F113F6002FC54B3ECe250d8B5"

# Paste ABI from Remix
abi_json =''' [
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "string",
				"name": "fileHash",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "filename",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "address",
				"name": "owner",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"name": "FileStored",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_filename",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_fileHash",
				"type": "string"
			}
		],
		"name": "storeFile",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_fileHash",
				"type": "string"
			}
		],
		"name": "getFile",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"name": "records",
		"outputs": [
			{
				"internalType": "string",
				"name": "filename",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "fileHash",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "owner",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]'''

abi = json.loads(abi_json)

contract = web3.eth.contract(address=contract_address, abi=abi)
account = web3.eth.accounts[0]  # Use first Ganache account

def store_file(filename, file_hash):
    tx_hash = contract.functions.storeFile(filename, file_hash).transact({'from': account})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"File stored on blockchain at tx: {receipt.transactionHash.hex()}")

def get_file(file_hash):
    result = contract.functions.getFile(file_hash).call()
    print("Retrieved record:", result)
    return result

# Example test
if __name__ == "__main__":
    store_file("sample.txt", "hash12345")
    get_file("hash12345")
