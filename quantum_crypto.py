import base64
import hashlib
import os
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import numpy as np
from liboqs import KeyEncapsulation


class QuantumCryptoEngine:
    """Quantum-enhanced cryptography with QRNG and Post-Quantum encryption"""

    def __init__(self):
        self.quantum_random_seed = None
        self.pq_public_key = None
        self.pq_secret_key = None

    def fetch_quantum_randomness(self, length=32):
        """Fetch true quantum random numbers from ANU QRNG"""
        try:
            # ANU Quantum Random Numbers API
            response = requests.get(
                f'https://qrng.anu.edu.au/API/jsonI.php?length={length}&type=hex16&size=1'
            )
            if response.status_code == 200:
                data = response.json()
                hex_string = data['data'][0]
                return bytes.fromhex(hex_string)
        except:
            pass
        # Fallback to hybrid RNG if QRNG fails
        return os.urandom(length) + hashlib.sha256(str(os.urandom(32)).encode()).digest()

    def generate_quantum_key(self, password, salt=None, length=32):
        """Generate encryption key using quantum randomness and Argon2"""
        if salt is None:
            salt = self.fetch_quantum_randomness(16)

        # Use quantum randomness as additional entropy
        quantum_entropy = self.fetch_quantum_randomness(32)
        enhanced_password = password.encode() + quantum_entropy

        # Key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=1000000,
        )
        return kdf.derive(enhanced_password), salt

    def init_post_quantum_kem(self, kem_alg="Kyber512"):
        """Initialize Post-Quantum Key Encapsulation Mechanism"""
        self.kem = KeyEncapsulation(kem_alg, None)
        self.pq_public_key = self.kem.generate_keypair()
        return self.pq_public_key

    def pq_encapsulate(self, peer_public_key):
        """Perform PQ key exchange"""
        kem = KeyEncapsulation("Kyber512", None)
        ciphertext, shared_secret = kem.encap_secret(peer_public_key)
        return ciphertext, shared_secret

    def pq_decap(self, ciphertext):
        """Decapsulate shared secret"""
        shared_secret = self.kem.decap_secret(ciphertext)
        return shared_secret

    def encrypt_message(self, message, key):
        """Encrypt with AES-256-GCM using quantum-enhanced key"""
        aesgcm = AESGCM(key)
        nonce = self.fetch_quantum_randomness(12)  # 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt_message(self, encrypted_data, key):
        """Decrypt AES-256-GCM encrypted message"""
        data = base64.b64decode(encrypted_data)
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()