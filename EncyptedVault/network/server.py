import socket
import struct
import os
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

# === Configuration ===
HOST = "0.0.0.0"
PORT = 9000
BUFFER_SIZE = 4096

PRIVATE_KEY_PATH = os.path.join("..", "crypto_utils", "private.pem")
OUTPUT_DIR = os.path.join("..", "received_files")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# === Utility Functions ===
def recv_exact(conn, n):
    """Receive exactly n bytes from the socket."""
    data = bytearray()
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            raise ConnectionError("Connection closed unexpectedly")
        data.extend(packet)
    return bytes(data)


def recv_varbytes(conn):
    """Receive a variable-length byte sequence with 4-byte prefix."""
    raw_len = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", raw_len)
    if length == 0:
        return b""
    return recv_exact(conn, length)


# === Client Handler Thread ===
def handle_client(conn, addr):
    try:
        print(f"[+] New connection from {addr}")

        # 1️⃣ Receive encrypted AES key
        enc_aes_key = recv_varbytes(conn)
        print(f"    Received AES key ({len(enc_aes_key)} bytes)")

        # 2️⃣ Receive filename
        filename = recv_varbytes(conn).decode("utf-8")
        safe_filename = os.path.basename(filename)
        print(f"    Filename: {safe_filename}")

        # 3️⃣ Receive plaintext digest
        digest = recv_exact(conn, 32)

        # 4️⃣ Receive encrypted file length + content
        (enc_len,) = struct.unpack("!Q", recv_exact(conn, 8))
        enc_path = os.path.join(OUTPUT_DIR, safe_filename + ".enc")

        with open(enc_path, "wb") as wf:
            remaining = enc_len
            while remaining:
                chunk = conn.recv(min(BUFFER_SIZE, remaining))
                if not chunk:
                    raise ConnectionError("Connection lost while receiving file")
                wf.write(chunk)
                remaining -= len(chunk)
        print(f"    File saved as {enc_path}")

        # 5️⃣ Decrypt AES key
        with open(PRIVATE_KEY_PATH, "rb") as f:
            priv = RSA.import_key(f.read())
        rsa_cipher = PKCS1_OAEP.new(priv)
        aes_key = rsa_cipher.decrypt(enc_aes_key)

        # 6️⃣ Decrypt file
        with open(enc_path, "rb") as f:
            iv = f.read(16)
            ciphertext = f.read()
        aes = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(aes.decrypt(ciphertext), AES.block_size)

        # Save decrypted file
        dec_path = os.path.join(OUTPUT_DIR, safe_filename)
        with open(dec_path, "wb") as f:
            f.write(plaintext)
        print(f"    Decrypted file -> {dec_path}")

        # 7️⃣ Verify integrity
        if sha256(plaintext).digest() == digest:
            print(f"    [OK] Integrity verified for {safe_filename}")
            conn.sendall(b"OK")
        else:
            print(f"    [FAIL] Digest mismatch for {safe_filename}")
            conn.sendall(b"FAIL")

    except Exception as e:
        print(f"[!] Error with client {addr}: {e}")
        try:
            conn.sendall(b"ERR")
        except:
            pass
    finally:
        conn.close()
        print(f"[-] Connection closed: {addr}")


# === Multi-threaded TCP Server ===
def main():
    print(f"[+] Starting multi-threaded server on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        print("[+] Server ready for clients...")

        while True:
            conn, addr = s.accept()
            # Each client handled in its own thread
            client_thread = threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            )
            client_thread.start()


if __name__ == "__main__":
    main()



"""
cd EncryptedVault/network
python server.py 
"""