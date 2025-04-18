from cryptography.fernet import Fernet
import hashlib

def encrypt_data(text, key):
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_text.encode()).decode()

def hash_passkey(passkey):
    return hashlib.pbkdf2_hmac('sha56',passkey.encode(),b'salt',100000).hex()