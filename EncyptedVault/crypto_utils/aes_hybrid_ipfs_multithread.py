#!/usr/bin/env python3
"""
aes_hybrid_ipfs_multithread.py

Multi-threaded:
- AES encryption
- RSA encryption of AES key
- Upload encrypted file to IPFS
- Store (filename, fileHash, encAesKeyB64, ipfsCid) on-chain
- Verify and decrypt

Requires:
- public.pem
- private.pem
- ipfs_uploader.py → upload_to_ipfs()
- FileVaultWithIPFS contract deployed
"""

import os
import sys
import json
import base64
import hashlib
import threading
import concurrent.futures
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from web3 import Web3

# Import the IPFS uploader
from ipfs_uploader import upload_to_ipfs

# =====================================================
# CONFIG - UPDATE THESE
# =====================================================

GANACHE_URL = "http://127.0.0.1:7545"

CONTRACT_ADDRESS = "0x03a56dFAaE443250846D225A89c24c42278c7A73"   # <-- EDIT

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
				"indexed": false,
				"internalType": "string",
				"name": "ipfsCid",
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
			},
			{
				"internalType": "string",
				"name": "_ipfsCid",
				"type": "string"
			}
		],
		"name": "storeFileWithKeyAndCID",
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
		"name": "getFileWithKeyAndCID",
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
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
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
			},
			{
				"internalType": "string",
				"name": "ipfsCid",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]'''  # <--- Replace with full ABI from Remix

RSA_PUBLIC_KEY = "public.pem"
RSA_PRIVATE_KEY = "private.pem"

MAX_WORKERS = 4

# =====================================================
# Blockchain init
# =====================================================

w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
if not w3.is_connected():
    print("❌ Cannot connect to Ganache")
    sys.exit(1)

print(f"[✓] Connected to Ganache | Chain ID: {w3.eth.chain_id}")

try:
    abi = json.loads(ABI_JSON)
except Exception as e:
    print("❌ ABI JSON error:", e)
    sys.exit(1)

contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)

if not w3.eth.accounts:
    print("❌ No accounts found in Ganache")
    sys.exit(1)

ACCOUNT = w3.eth.accounts[0]
print(f"[✓] Using account: {ACCOUNT}")

tx_lock = threading.Lock()

# =====================================================
# Crypto helpers
# =====================================================

def aes_encrypt_bytes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ct

def aes_decrypt_bytes(enc_blob, key):
    iv = enc_blob[:16]
    ct = enc_blob[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def rsa_encrypt_key(aes_key, pub_path: Path):
    pub = RSA.import_key(pub_path.read_bytes())
    cipher_rsa = PKCS1_OAEP.new(pub)
    return cipher_rsa.encrypt(aes_key)

def rsa_decrypt_key(enc_key_bytes, priv_path: Path):
    priv = RSA.import_key(priv_path.read_bytes())
    cipher_rsa = PKCS1_OAEP.new(priv)
    return cipher_rsa.decrypt(enc_key_bytes)

def sha256_file(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# =====================================================
# Worker process
# =====================================================

def process_file(file_path: Path, output_dir: Path, pub: Path, priv: Path):

    filename = file_path.name
    encrypted_file = output_dir / f"encrypted__{filename}"
    encrypted_key_file = output_dir / f"enc_key__{filename}.b64"
    decrypted_file = output_dir / f"decrypted__{filename}"

    try:
        # Read file
        plain = file_path.read_bytes()

        # AES key
        aes_key = get_random_bytes(16)

        # AES encrypt
        enc_blob = aes_encrypt_bytes(plain, aes_key)
        encrypted_file.write_bytes(enc_blob)
        print(f"[Encrypt] Saved: {encrypted_file}")

        # RSA encrypt AES key
        rsa_enc_key = rsa_encrypt_key(aes_key, pub)
        enc_key_b64 = base64.b64encode(rsa_enc_key).decode()
        encrypted_key_file.write_text(enc_key_b64)

        # IPFS upload
        print("[IPFS] Uploading encrypted file...")
        cid = upload_to_ipfs(str(encrypted_file))
        print(f"[IPFS] CID: {cid}")

        # Hash
        file_hash = sha256_file(encrypted_file)
        print(f"[HASH] {filename} → {file_hash}")

        # Blockchain TX
        with tx_lock:
            tx = contract.functions.storeFileWithKeyAndCID(
                filename,
                file_hash,
                enc_key_b64,
                cid
            ).transact({'from': ACCOUNT})
            receipt = w3.eth.wait_for_transaction_receipt(tx)
            print(f"[BC] Stored on-chain: Tx={tx.hex()}")

        # Verify on-chain
        rec = contract.functions.getFileWithKeyAndCID(file_hash).call()
        print(f"[BC] On-chain CID: {rec[5]}")

        # RSA decrypt AES key
        recovered_key = rsa_decrypt_key(base64.b64decode(rec[4]), priv)

        # AES decrypt file
        decrypted_plain = aes_decrypt_bytes(enc_blob, recovered_key)
        decrypted_file.write_bytes(decrypted_plain)
        print(f"[Decrypt] Saved: {decrypted_file}")

        return True

    except Exception as e:
        print(f"[ERROR] {filename}: {e}")
        return False


# =====================================================
# Directory processor
# =====================================================

def process_directory(input_dir: Path, output_dir: Path, workers: int):
    pub = Path(RSA_PUBLIC_KEY)
    priv = Path(RSA_PRIVATE_KEY)

    if not pub.exists() or not priv.exists():
        print("❌ RSA public/private keys missing")
        sys.exit(1)

    files = [f for f in input_dir.iterdir() if f.is_file()]
    if not files:
        print("No files found:", input_dir)
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Start] Processing {len(files)} files with {workers} threads...")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(process_file, f, output_dir, pub, priv): f for f in files}

        for fut in concurrent.futures.as_completed(futures):
            src = futures[fut]
            ok = fut.result()
            print(f"[Done] {src.name}: {'OK' if ok else 'FAIL'}")
            results.append((src.name, ok))

    print("\n=== SUMMARY ===")
    for name, ok in results:
        print(f"{name}: {'OK' if ok else 'FAIL'}")


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python aes_hybrid_ipfs_multithread.py input_dir [output_dir] [workers]")
        sys.exit(1)

    input_dir = Path(sys.argv[1])

    if not input_dir.exists():
        print("❌ Input directory does not exist:", input_dir)
        sys.exit(1)

    output_dir = Path(sys.argv[2]) if len(sys.argv) >= 3 else input_dir / "processed_ipfs"
    workers = int(sys.argv[3]) if len(sys.argv) >= 4 else MAX_WORKERS

    process_directory(input_dir, output_dir, workers)
