from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

def pad(text):
    # to Pad text to be a multiple of 16 bytes
    padding_length = 16 - len(text) % 16
    return text + chr(padding_length) * padding_length

def unpad(text):
    # Remove padding
    padding_length = ord(text[-1])
    return text[:-padding_length]

def encrypt(key, plaintext):
    key = hashlib.sha256(key.encode()).digest()  
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext).encode('utf-8'))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt(key, iv, ciphertext):
    key = hashlib.sha256(key.encode()).digest()
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return unpad(pt.decode('utf-8'))

def main():
    print("AES Encryption/Decryption")

    key = input("Enter encryption key (password): ")
    plaintext = input("Enter plaintext message to encrypt: ")

    iv, encrypted = encrypt(key, plaintext)
    print(f"\nEncrypted message: {encrypted}")
    print(f"Initialization Vector (IV): {iv}")

    # Decryption
    decrypt_choice = input("\nDo you want to decrypt the message? (yes/no): ").lower()
    if decrypt_choice == 'yes':
        decryption_key = input("Enter the same encryption key (password) for decryption: ")
        try:
            decrypted = decrypt(decryption_key, iv, encrypted)
            print(f"Decrypted message: {decrypted}")
        except Exception as e:
            print(f"Decryption failed: {str(e)}")

if __name__ == '__main__':
    main()
