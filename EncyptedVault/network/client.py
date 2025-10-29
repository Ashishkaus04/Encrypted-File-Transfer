import socket
import struct
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from hashlib import sha256

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000
BUFFER_SIZE = 4096

SERVER_PUBKEY_PATH = os.path.join("..", "crypto_utils", "public.pem")  # server public key

def send_varbytes(s, bts):
    """Send length-prefixed bytes (4-byte unsigned int)."""
    s.sendall(struct.pack("!I", len(bts)))
    if len(bts) > 0:
        s.sendall(bts)

def send_file_encrypted(filepath):
    filename = os.path.basename(filepath)

    # Read plaintext
    with open(filepath, "rb") as f:
        plaintext = f.read()

    # Generate AES key and encrypt plaintext (CBC + IV)
    aes_key = get_random_bytes(16)  # 128-bit key
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    enc_blob = iv + ciphertext  # prepend IV

    # Encrypt AES key with server public key (RSA-OAEP)
    with open(SERVER_PUBKEY_PATH, "rb") as f:
        pub = RSA.import_key(f.read())
    rsa_cipher = PKCS1_OAEP.new(pub)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    # Compute SHA256 digest of plaintext
    digest = sha256(plaintext).digest()

    # Connect and send:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}")

        # 1) Send encrypted AES key (4-byte length + bytes)
        send_varbytes(s, enc_aes_key)
        print(f"    Sent encrypted AES key ({len(enc_aes_key)} bytes)")

        # 2) Send filename (4-byte length + UTF-8 bytes)
        send_varbytes(s, filename.encode("utf-8"))
        print(f"    Sent filename: {filename}")

        # 3) Send digest (exact 32 bytes)
        s.sendall(digest)
        print(f"    Sent SHA256 digest: {digest.hex()}")

        # 4) Send encrypted file length (8 bytes) then file bytes in chunks
        s.sendall(struct.pack("!Q", len(enc_blob)))
        sent = 0
        view = memoryview(enc_blob)
        while sent < len(enc_blob):
            chunk = view[sent:sent+BUFFER_SIZE]
            s.sendall(chunk)
            sent += len(chunk)
        print(f"    Sent encrypted file ({len(enc_blob)} bytes)")

        # 5) Wait for server response
        status = s.recv(4)
        print("    Server response:", status.decode() if status else "(no response)")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Client: send encrypted file to server")
    parser.add_argument("file", help="Path to file to send")
    parser.add_argument("--host", default=SERVER_HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    args = parser.parse_args()

    SERVER_HOST = args.host
    SERVER_PORT = args.port

    send_file_encrypted(args.file)


"""
cd EncryptedVault/network
python client.py ../test_files/sample.txt  

The file to be sent stored in test_files but is received in received_files with both encrypt and decrypt files
change the file u want to send"""