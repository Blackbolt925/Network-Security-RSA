from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import base64

def pad(text):
    # Pad the text to be a multiple of 8 bytes (DES block size)
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_CBC)
    padded_text = pad(plaintext)
    ct_bytes = cipher.encrypt(padded_text.encode('utf-8'))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt(key, iv, ciphertext):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return pt.decode('utf-8').rstrip(' ')

def main():
    print("DES Encryption/Decryption")
    key_input = input("Enter 8-character encryption key: ")

    if len(key_input) != 8:
        print("Key must be exactly 8 characters long!")
        return

    key = key_input.encode('utf-8')
    plaintext = input("Enter plaintext message to encrypt: ")

    iv, encrypted = encrypt(key, plaintext)
    print(f"\nEncrypted message: {encrypted}")
    print(f"Initialization Vector (IV): {iv}")

    # Decryption
    decrypt_choice = input("\nDo you want to decrypt the message? (yes/no): ").lower()
    if decrypt_choice == 'yes':
        decryption_key_input = input("Enter the same 8-character key for decryption: ")
        if len(decryption_key_input) != 8:
            print("Key must be exactly 8 characters!")
            return

        decryption_key = decryption_key_input.encode('utf-8')
        try:
            decrypted = decrypt(decryption_key, iv, encrypted)
            print(f"Decrypted message: {decrypted}")
        except Exception as e:
            print(f"Decryption failed: {str(e)}")

if __name__ == '__main__':
    main()
