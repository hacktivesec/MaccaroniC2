# Routines for encrypting/decrypting with Fernet

import base64
import hashlib

from cryptography.fernet import Fernet

def generate_key_from_password(password):
    # Convert the password to bytes and take the SHA256 hash
    password_hash = hashlib.sha256(password.encode()).digest()

    # Use the first 32 bytes of the password hash as the key
    key = base64.urlsafe_b64encode(password_hash[:32])
    return key


def encrypt_with_password(message, password):
    key = generate_key_from_password(password)
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message, key


def decrypt_with_password(encrypted_message, password):
    key = generate_key_from_password(password)
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()


password = 'P4ssw0rd!' # Password to encrypt/decrypt
message = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' # Plaintext Ngrok AUTH Token
encrypted_message, key = encrypt_with_password(message, password)
decrypted_message = decrypt_with_password(encrypted_message, password)


print('Original String:', message)
print('Encrypted String:', encrypted_message)
print('Decrypted String:', decrypted_message)
