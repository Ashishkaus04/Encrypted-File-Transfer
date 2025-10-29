from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def sign_file(file_path, private_key_file):
    key = RSA.import_key(open(private_key_file).read())
    h = SHA256.new(open(file_path, 'rb').read())
    signature = pkcs1_15.new(key).sign(h)
    with open(file_path + ".sig", 'wb') as f:
        f.write(signature)
    print(f"[+] File signed: {file_path}.sig")

def verify_signature(file_path, signature_file, public_key_file):
    key = RSA.import_key(open(public_key_file).read())
    h = SHA256.new(open(file_path, 'rb').read())
    signature = open(signature_file, 'rb').read()
    try:
        pkcs1_15.new(key).verify(h, signature)
        print("[+] Signature valid.")
    except (ValueError, TypeError):
        print("[!] Signature verification failed.")
