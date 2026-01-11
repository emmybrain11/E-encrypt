import base64
import hashlib

def encrypt_message(message: str) -> str:
    hashed = hashlib.sha256(message.encode()).digest()
    return base64.b64encode(hashed).decode()

def decrypt_message(cipher: str) -> str:
    return "[Encrypted Message]"
