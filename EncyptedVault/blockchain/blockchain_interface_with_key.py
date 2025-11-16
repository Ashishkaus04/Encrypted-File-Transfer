from web3 import Web3
import json
import base64

# 1️⃣ Connect to Ganache blockchain
GANACHE_URL = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(GANACHE_URL))

if not web3.is_connected():
    raise Exception("❌ Could not connect to Ganache")

print(f"[✓] Connected to chain: ID {web3.eth.chain_id}")

# 2️⃣ Paste your deployed contract address
CONTRACT_ADDRESS = "0xbF90eAD2Aa2753cC1daEC38372F49f55f4Ad991F"

# 3️⃣ Paste your ABI from Remix (as JSON string)
ABI_JSON = '''[
  
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
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
				"indexed": true,
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
			},
			{
				"internalType": "string",
				"name": "_encAesKeyB64",
				"type": "string"
			}
		],
		"name": "storeFileWithKey",
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
		"name": "getFileWithKey",
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
			},
			{
				"internalType": "string",
				"name": "encAesKeyB64",
				"type": "string"
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
			},
			{
				"internalType": "string",
				"name": "encAesKeyB64",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]
'''

abi = json.loads(ABI_JSON)
contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)
account = web3.eth.accounts[0]

# 4️⃣ Define blockchain helper functions

def store_file_with_key(filename, file_hash, enc_aes_key_b64):
    """Store encrypted AES key and metadata on-chain."""
    tx = contract.functions.storeFileWithKey(filename, file_hash, enc_aes_key_b64).transact({'from': account})
    receipt = web3.eth.wait_for_transaction_receipt(tx)
    print(f"[+] Stored {filename} ({file_hash[:8]}...) on-chain | Tx: {receipt.transactionHash.hex()}")
    return receipt

def get_file_with_key(file_hash):
    """Fetch stored file record including RSA-encrypted AES key."""
    rec = contract.functions.getFileWithKey(file_hash).call()
    print("\n[+] On-chain Record:")
    print(f"   Filename   : {rec[0]}")
    print(f"   File Hash  : {rec[1]}")
    print(f"   Owner Addr : {rec[2]}")
    print(f"   Timestamp  : {rec[3]}")
    print(f"   Encrypted AES key (base64): {rec[4]}")
    return rec
