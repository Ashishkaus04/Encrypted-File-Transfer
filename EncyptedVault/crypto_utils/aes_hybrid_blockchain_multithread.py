#!/usr/bin/env python3
"""
aes_hybrid_blockchain_multithread.py

Multi-threaded hybrid encryption (AES + RSA) + blockchain logging.

Each file workflow:
  AES encrypt file  → RSA encrypt AES key → store encrypted file
  → compute hash → store on blockchain (filename, hash, encAESKeyB64)
  → retrieve from blockchain → RSA decrypt AES key → AES decrypt file

Usage:
    python aes_hybrid_blockchain_multithread.py input_dir
"""

import os
import sys
import json
import base64
import hashlib
import threading
import concurrent.futures
from pathlib import Path
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from web3 import Web3

# ============================================================
# CONFIG (EDIT THESE)
# ============================================================

GANACHE_URL = "http://127.0.0.1:7545"

CONTRACT_ADDRESS = "0xbF90eAD2Aa2753cC1daEC38372F49f55f4Ad991F"   # <-- EDIT
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
]'''  # <-- EDIT if your ABI differs

MAX_WORKERS = 4  # threads

# RSA KEYS — these must exist
RSA_PUBLIC_KEY = "public.pem"
RSA_PRIVATE_KEY = "private.pem"


# ============================================================
# Blockchain setup
# ============================================================

tx_lock = threading.Lock()

w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
if not w3.is_connected():
    print("❌ Could not connect to Ganache. Start Ganache first.")
    sys.exit(1)

print(f"[✓] Connected to blockchain | Chain ID = {w3.eth.chain_id}")

try:
    abi = json.loads(ABI_JSON)
except:
    print("❌ ABI_JSON is invalid. Ensure it's valid JSON.")
    sys.exit(1)

contract = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=abi
)

ACCOUNT = w3.eth.accounts[0]
print(f"[✓] Using account: {ACCOUNT}")


# ============================================================
# Encryption helpers
# ============================================================

def aes_encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ct


def aes_decrypt_bytes(enc_blob: bytes, key: bytes) -> bytes:
    iv = enc_blob[:16]
    ciphertext = enc_blob[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def rsa_encrypt_key(aes_key: bytes, rsa_pub_path: Path) -> bytes:
    pub_key = RSA.import_key(rsa_pub_path.read_bytes())
    rsa_cipher = PKCS1_OAEP.new(pub_key)
    return rsa_cipher.encrypt(aes_key)


def rsa_decrypt_key(enc_key: bytes, rsa_priv_path: Path) -> bytes:
    priv = RSA.import_key(rsa_priv_path.read_bytes())
    rsa_cipher = PKCS1_OAEP.new(priv)
    return rsa_cipher.decrypt(enc_key)


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# ============================================================
# Per-file processing (runs inside worker threads)
# ============================================================

def process_file(file_path: Path, output_dir: Path, pub_key_path: Path, priv_key_path: Path):
    filename = file_path.name
    enc_file = output_dir / f"encrypted__{filename}"
    enc_key_file = output_dir / f"enc_key__{filename}.b64"
    dec_file = output_dir / f"decrypted__{filename}"

    try:
        # ---- read plaintext ----
        data = file_path.read_bytes()

        # ---- generate AES key ----
        aes_key = get_random_bytes(16)

        # ---- AES encrypt ----
        enc_blob = aes_encrypt_bytes(data, aes_key)
        enc_file.write_bytes(enc_blob)
        print(f"[T{threading.get_ident()}] Encrypted: {enc_file}")

        # ---- RSA encrypt AES key ----
        rsa_enc_key = rsa_encrypt_key(aes_key, pub_key_path)
        enc_key_b64 = base64.b64encode(rsa_enc_key).decode()
        enc_key_file.write_text(enc_key_b64)
        print(f"[T{threading.get_ident()}] AES Key (RSA-wrapped) saved: {enc_key_file}")

        # ---- compute hash ----
        file_hash = sha256_file(enc_file)
        print(f"[T{threading.get_ident()}] Hash: {file_hash}")

        # ---- blockchain transaction (serialized) ----
        with tx_lock:
            tx_hash = contract.functions.storeFileWithKey(
                filename,
                file_hash,
                enc_key_b64
            ).transact({'from': ACCOUNT})

            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"[T{threading.get_ident()}] Tx mined: {tx_hash.hex()}")

        # ---- read back from chain ----
        onchain = contract.functions.getFileWithKey(file_hash).call()
        print(f"[T{threading.get_ident()}] On-chain record OK")

        # ---- RSA decrypt AES key & verify ----
        rsa_enc_key_bytes = base64.b64decode(enc_key_b64)
        recovered_aes_key = rsa_decrypt_key(rsa_enc_key_bytes, priv_key_path)

        recovered_plain = aes_decrypt_bytes(enc_blob, recovered_aes_key)
        dec_file.write_bytes(recovered_plain)
        print(f"[T{threading.get_ident()}] Decrypted OK: {dec_file}")

        return True

    except Exception as e:
        print(f"[T{threading.get_ident()}] ERROR processing {filename}: {e}")
        return False


# ============================================================
# Directory processing
# ============================================================

def process_directory(input_dir: Path, output_dir: Path):
    pub = Path(RSA_PUBLIC_KEY)
    priv = Path(RSA_PRIVATE_KEY)

    if not pub.exists() or not priv.exists():
        print("❌ Missing RSA keys. Generate using rsa_keygen.py")
        sys.exit(1)

    files = [f for f in input_dir.iterdir() if f.is_file()]
    if not files:
        print("No files found.")
        return

    output_dir.mkdir(exist_ok=True)

    print(f"[+] Processing {len(files)} files using {MAX_WORKERS} threads...\n")

    with concurrent.futures.ThreadPoolExecutor(MAX_WORKERS) as ex:
        futures = {ex.submit(process_file, f, output_dir, pub, priv): f for f in files}

        for fut in concurrent.futures.as_completed(futures):
            file = futures[fut]
            try:
                ok = fut.result()
                print(f"[✓] Completed: {file.name}" if ok else f"[✗] Failed: {file.name}")
            except Exception as e:
                print(f"[✗] Error: {file.name} → {e}")

    print("\n[✓] All tasks finished.")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python aes_hybrid_blockchain_multithread.py input_dir")
        sys.exit(1)

    input_dir = Path(sys.argv[1])
    output_dir = input_dir / "processed_output"

    process_directory(input_dir, output_dir)
