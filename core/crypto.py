
import base64

class SimpleCrypto:
    def encrypt(self, text):
        return base64.b64encode(text.encode()).decode()

    def decrypt(self, secret):
        return base64.b64decode(secret.encode()).decode()