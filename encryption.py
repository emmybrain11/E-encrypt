import os
import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hmac


class AES256Encryptor:
    """Advanced AES-256 encryption with multiple modes"""

    def __init__(self):
        self.key_storage = "data/keys/"
        os.makedirs(self.key_storage, exist_ok=True)
        self.session_keys = {}
        self.duress_key = None

    def generate_keys(self, password):
        """Generate master encryption keys from password"""
        # Generate salt
        salt = os.urandom(32)

        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,  # 512-bit key
            salt=salt,
            iterations=1000000,  # High iteration count for security
            backend=default_backend()
        )

        key_material = kdf.derive(password.encode())
        master_key = key_material[:32]  # 256-bit AES key
        hmac_key = key_material[32:]  # 256-bit HMAC key

        # Save keys securely
        self.save_key("master_key", master_key, salt)
        self.save_key("hmac_key", hmac_key)

        # Generate RSA key pair
        self.generate_rsa_keys(password)

        return master_key

    def generate_rsa_keys(self, password):
        """Generate RSA 4096-bit key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        # Serialize and save
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode()
            )
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(f"{self.key_storage}private.pem", "wb") as f:
            f.write(private_pem)

        with open(f"{self.key_storage}public.pem", "wb") as f:
            f.write(public_pem)

    def aes_encrypt(self, plaintext, key=None, mode="GCM"):
        """Encrypt text using AES-256 with specified mode"""
        if key is None:
            key = self.load_key("master_key")

        # Generate random IV
        iv = os.urandom(16)

        if mode == "GCM":
            # AES-GCM for authenticated encryption
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
            tag = encryptor.tag

            # Combine IV, ciphertext, and tag
            encrypted_data = iv + tag + ciphertext

        elif mode == "CBC":
            # AES-CBC with PKCS7 padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()

            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = iv + ciphertext

        else:
            raise ValueError(f"Unsupported mode: {mode}")

        # Add HMAC for integrity
        hmac_key = self.load_key("hmac_key")
        signature = hmac.new(hmac_key, encrypted_data, hashlib.sha256).digest()

        return base64.b64encode(signature + encrypted_data).decode()

    def aes_decrypt(self, encrypted_data, key=None, mode="GCM"):
        """Decrypt AES-256 encrypted data"""
        if key is None:
            key = self.load_key("master_key")

        data = base64.b64decode(encrypted_data)

        # Verify HMAC
        hmac_key = self.load_key("hmac_key")
        signature = data[:32]
        encrypted = data[32:]

        expected_signature = hmac.new(hmac_key, encrypted, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("HMAC verification failed - data may be tampered")

        if mode == "GCM":
            # Extract components
            iv = encrypted[:16]
            tag = encrypted[16:32]
            ciphertext = encrypted[32:]

            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        elif mode == "CBC":
            iv = encrypted[:16]
            ciphertext = encrypted[16:]

            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        else:
            raise ValueError(f"Unsupported mode: {mode}")

        return plaintext.decode()

    def aes_encrypt_binary(self, binary_data, key=None):
        """Encrypt binary data (files, images)"""
        if key is None:
            key = self.load_key("master_key")

        # Generate random IV
        iv = os.urandom(16)

        # Use CTR mode for binary data
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(binary_data) + encryptor.finalize()

        # Return IV + ciphertext
        return iv + ciphertext

    def aes_decrypt_binary(self, encrypted_data, key=None):
        """Decrypt binary data"""
        if key is None:
            key = self.load_key("master_key")

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()

    def generate_session_key(self):
        """Generate ephemeral session key for calls"""
        session_key = os.urandom(32)
        session_id = hashlib.sha256(session_key).hexdigest()[:16]
        self.session_keys[session_id] = session_key
        return session_id, session_key

    def rsa_encrypt(self, data, public_key_pem):
        """Encrypt with RSA public key"""
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

        encrypted = public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted

    def rsa_decrypt(self, encrypted_data, password):
        """Decrypt with RSA private key"""
        with open(f"{self.key_storage}private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode(),
                backend=default_backend()
            )

        decrypted = private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted

    def save_key(self, key_name, key_data, salt=None):
        """Save key securely"""
        key_path = f"{self.key_storage}{key_name}.key"

        with open(key_path, "wb") as f:
            if salt:
                f.write(salt + key_data)
            else:
                f.write(key_data)

        # Set restrictive permissions
        if os.name != 'nt':  # Unix-like systems
            os.chmod(key_path, 0o600)

    def load_key(self, key_name):
        """Load saved key"""
        key_path = f"{self.key_storage}{key_name}.key"

        with open(key_path, "rb") as f:
            data = f.read()

        # For master key, first 32 bytes are salt
        if key_name == "master_key":
            return data[32:]  # Skip salt
        else:
            return data

    def set_duress_key(self, duress_password):
        """Set duress key for emergency mode"""
        # Generate different key from duress password
        salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=10000,
            backend=default_backend()
        )

        self.duress_key = kdf.derive(duress_password.encode())
        self.save_key("duress_key", self.duress_key, salt)

    def wipe_all_keys(self):
        """Securely wipe all encryption keys"""
        import shutil

        # Overwrite keys with random data before deletion
        for root, dirs, files in os.walk(self.key_storage):
            for file in files:
                filepath = os.path.join(root, file)
                size = os.path.getsize(filepath)

                # Overwrite multiple times
                for _ in range(3):
                    with open(filepath, "wb") as f:
                        f.write(os.urandom(size))

                os.remove(filepath)

        # Remove directory
        shutil.rmtree(self.key_storage)

        # Clear memory
        self.session_keys.clear()
        self.duress_key = None