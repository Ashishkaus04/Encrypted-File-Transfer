"""
aes_blockchain_multithread.py

Multi-threaded AES encrypt + blockchain logging + verify-decrypt for a directory of files.

Usage:
    python aes_blockchain_multithread.py /path/to/input_dir

Requirements:
    - web3
    - pycryptodome
    - Ganache running and FileVault deployed
    - Fill CONTRACT_ADDRESS and ABI_JSON below

Behavior:
    - For each file in input_dir (non-recursive), a worker thread:
        1) encrypts -> output_dir/encrypted_<filename>
        2) computes SHA256 of encrypted file
        3) serializes tx (acquires tx_lock) and calls contract.storeFile(filename, filehash)
        4) waits for receipt
        5) decrypts to output_dir/decrypted_<filename> (to verify)
    - Prints progress and errors
"""

import os
import sys
import json
import hashlib
import threading
import concurrent.futures
from pathlib import Path
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from web3 import Web3

# -----------------------------
# CONFIG — fill these values
# -----------------------------
GANACHE_URL = "http://127.0.0.1:7545"
CONTRACT_ADDRESS = "0x89d4bf9Daf68103F113F6002FC54B3ECe250d8B5"   # <-- paste your deployed FileVault address
ABI_JSON = '''
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
'''  # <-- replace or keep, but ensure it's valid JSON (true/false/null lowercase)

# Threading / concurrency
MAX_WORKERS = 4   # number of parallel encrypt/hash workers. Adjust to CPU.

# -----------------------------
# Globals and helpers
# -----------------------------
tx_lock = threading.Lock()  # serialize blockchain transactions to avoid nonce issues

# Web3 + contract will be initialized once (main thread) and used by workers (transactions serialized)
w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
if not w3.is_connected():
    print("❌ Unable to connect to Ganache at", GANACHE_URL)
    sys.exit(1)

try:
    contract_abi = json.loads(ABI_JSON)
except Exception as e:
    print("❌ Failed to parse ABI_JSON. Make sure ABI JSON (with lowercase booleans) is pasted into ABI_JSON.")
    raise

contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=contract_abi)

# Use the first Ganache account; ensure this account exists in your Ganache node
ACCOUNT = w3.eth.accounts[0]
print(f"[+] Connected to Ganache (chain_id={w3.eth.chain_id}). Using account: {ACCOUNT}")


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ct  # prepend IV


def decrypt_bytes(enc_blob: bytes, key: bytes) -> bytes:
    iv = enc_blob[:16]
    ciphertext = enc_blob[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def compute_hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def process_file(file_path: Path, output_dir: Path) -> Tuple[Path, str]:
    """
    Encrypt file, compute hash, send storeFile tx (serialized), decrypt for verification.
    Returns tuple(encrypted_file_path, file_hash)
    """
    filename = file_path.name
    enc_name = f"encrypted__{filename}"
    dec_name = f"decrypted__{filename}"
    enc_path = output_dir / enc_name
    dec_path = output_dir / dec_name

    try:
        # read plaintext
        with file_path.open("rb") as f:
            plaintext = f.read()

        # generate AES key for this file
        key = get_random_bytes(16)  # 128-bit
        enc_blob = encrypt_bytes(plaintext, key)

        # ensure output dir
        output_dir.mkdir(parents=True, exist_ok=True)

        # write encrypted file
        with enc_path.open("wb") as f:
            f.write(enc_blob)
        print(f"[T{threading.get_ident()}] Encrypted -> {enc_path}")

        # compute hash of encrypted file
        file_hash = compute_hash_file(enc_path)
        print(f"[T{threading.get_ident()}] Hash({filename}) = {file_hash}")

        # store on blockchain (serialized)
        with tx_lock:
            print(f"[T{threading.get_ident()}] Sending tx for {filename} ...")
            try:
                tx_hash = contract.functions.storeFile(filename, file_hash).transact({'from': ACCOUNT})
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                print(f"[T{threading.get_ident()}] Tx mined: {tx_hash.hex()} (status={receipt.status})")
            except Exception as e:
                print(f"[T{threading.get_ident()}] ERROR sending tx for {filename}: {e}")
                raise

        # optionally verify by calling getFile
        try:
            stored = contract.functions.getFile(file_hash).call()
            # stored => (filename, fileHash, owner, timestamp)
            print(f"[T{threading.get_ident()}] On-chain record: {stored}")
        except Exception as e:
            print(f"[T{threading.get_ident()}] ERROR reading back record: {e}")

        # decrypt into dec_path for verification
        try:
            dec_plain = decrypt_bytes(enc_blob, key)
            with dec_path.open("wb") as f:
                f.write(dec_plain)
            print(f"[T{threading.get_ident()}] Decrypted -> {dec_path}")
        except Exception as e:
            print(f"[T{threading.get_ident()}] Decryption error for {filename}: {e}")
            raise

        return enc_path, file_hash

    except Exception as e:
        print(f"[T{threading.get_ident()}] Failed processing {file_path}: {e}")
        return None, None


def process_directory(input_dir: Path, output_dir: Path, max_workers: int = MAX_WORKERS):
    files = [p for p in input_dir.iterdir() if p.is_file()]
    if not files:
        print("No files found in", input_dir)
        return

    print(f"Found {len(files)} files. Starting {max_workers} worker threads...")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(process_file, p, output_dir): p for p in files}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            try:
                enc_path, file_hash = fut.result()
                if enc_path is not None:
                    results.append((p.name, enc_path, file_hash))
            except Exception as e:
                print(f"Worker error for {p}: {e}")

    print("\n=== SUMMARY ===")
    for name, enc_path, fh in results:
        print(f"{name} -> {enc_path}  hash={fh}")


# -----------------------------
# CLI
# -----------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python aes_blockchain_multithread.py /path/to/input_dir [output_dir] [workers]")
        sys.exit(1)

    input_dir = Path(sys.argv[1])
    if not input_dir.exists() or not input_dir.is_dir():
        print("Input directory does not exist:", input_dir)
        sys.exit(1)

    output_dir = Path(sys.argv[2]) if len(sys.argv) >= 3 else input_dir / "processed_out"
    workers = int(sys.argv[3]) if len(sys.argv) >= 4 else MAX_WORKERS

    print(f"Input: {input_dir}")
    print(f"Output: {output_dir}")
    print(f"Workers: {workers}")

    process_directory(input_dir, output_dir, max_workers=workers)


if __name__ == "__main__":
    main()
