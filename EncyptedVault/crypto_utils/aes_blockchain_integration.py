from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from web3 import Web3
import hashlib
import json
import os
import sys

# ==============================
# 🔐 AES ENCRYPTION / DECRYPTION
# ==============================

def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    with open(output_file, 'wb') as f:
        f.write(cipher.iv + ciphertext)
    print(f"[+] File encrypted: {output_file}")

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"[+] File decrypted: {output_file}")

def compute_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

# ==============================
# ⛓️ BLOCKCHAIN CONNECTION SETUP
# ==============================

ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

if not web3.is_connected():
    print("❌ Unable to connect to Ganache. Make sure Ganache is running on port 7545.")
    sys.exit(1)

print(f"[✓] Connected to blockchain | Chain ID: {web3.eth.chain_id}")

# Paste your deployed contract address here
contract_address = "0x89d4bf9Daf68103F113F6002FC54B3ECe250d8B5"  # <-- CHANGE THIS

# Paste your ABI from Remix here (make sure 'false' is 'False')
abi_json = '''
[
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
]
'''

abi = json.loads(abi_json)
contract = web3.eth.contract(address=contract_address, abi=abi)

# Use first Ganache account
account = web3.eth.accounts[0]
print(f"[✓] Using account: {account}")

# ==============================
# 🧩 MAIN EXECUTION
# ==============================

if __name__ == "__main__":
    try:
        input_file = "../test_files/sample.txt"
        encrypted_file = "../test_files/encrypted.bin"
        decrypted_file = "../test_files/decrypted.txt"

        # check file existence
        if not os.path.exists(input_file):
            print(f"❌ Input file not found: {input_file}")
            sys.exit(1)

        key = get_random_bytes(16)  # AES 128-bit
        encrypt_file(input_file, encrypted_file, key)

        # compute SHA256 hash
        file_hash = compute_hash(encrypted_file)
        print(f"[+] SHA256 hash: {file_hash}")

        # store metadata on blockchain
        print("[*] Storing file metadata on blockchain...")
        tx_hash = contract.functions.storeFile(os.path.basename(input_file), file_hash).transact({'from': account})
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"[✓] Blockchain transaction complete: {tx_hash.hex()}")

        # verify stored record
        record = contract.functions.getFile(file_hash).call()
        print("\n[+] Blockchain record:")
        print(f"   Filename   : {record[0]}")
        print(f"   File Hash  : {record[1]}")
        print(f"   Owner Addr : {record[2]}")
        print(f"   Timestamp  : {record[3]}")

        # decrypt to verify
        decrypt_file(encrypted_file, decrypted_file, key)
        print("[✓] End-to-end encryption + blockchain logging successful ✅")

    except Exception as e:
        print(f"[!] Error: {e}")
