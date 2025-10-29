from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)
    print("[+] RSA key pair generated.")

def encrypt_key(aes_key, public_key_file):
    public_key = RSA.import_key(open(public_key_file).read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

def decrypt_key(encrypted_key, private_key_file):
    private_key = RSA.import_key(open(private_key_file).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    return decrypted_key

if __name__ == "__main__":
    generate_keys()

#run the file
from Crypto.Random import get_random_bytes
from rsa_keypair import encrypt_key, decrypt_key

aes_key = get_random_bytes(16)
enc_key = encrypt_key(aes_key, "public.pem")
dec_key = decrypt_key(enc_key, "private.pem")
print(aes_key == dec_key)  # should print True
