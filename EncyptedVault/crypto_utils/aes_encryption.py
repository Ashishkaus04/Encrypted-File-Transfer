from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# AES key length can be 16, 24, or 32 bytes
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

#run the file
if __name__ == "__main__":
    key = get_random_bytes(16)  # 128-bit key
    encrypt_file("../test_files/sample.txt", "../test_files/encrypted.bin", key)
    decrypt_file("../test_files/encrypted.bin", "../test_files/decrypted.txt", key)
