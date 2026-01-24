"""
Example Python client for E-Encrypt Backend API
"""

import requests
import json
import base64
from typing import Optional


class EEncryptClient:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.token = None
        self.user_id = None

    def register(self, username: str, password: str, email: Optional[str] = None):
        """Register new user"""
        url = f"{self.base_url}/api/auth/register"
        data = {
            "username": username,
            "password": password,
            "email": email
        }
        response = requests.post(url, json=data)
        return response.json()

    def login(self, username: str, password: str):
        """Login user"""
        url = f"{self.base_url}/api/auth/login"
        data = {
            "username": username,
            "password": password
        }
        response = requests.post(url, json=data)

        if response.status_code == 200:
            data = response.json()
            self.token = data["access_token"]
            self.user_id = data["user"]["id"]
            return data
        else:
            raise Exception(f"Login failed: {response.json()}")

    def get_headers(self):
        """Get authentication headers"""
        if not self.token:
            raise Exception("Not authenticated")
        return {"Authorization": f"Bearer {self.token}"}

    def get_profile(self):
        """Get current user profile"""
        url = f"{self.base_url}/api/users/me"
        response = requests.get(url, headers=self.get_headers())
        return response.json()

    def get_users(self):
        """Get all users"""
        url = f"{self.base_url}/api/users"
        response = requests.get(url, headers=self.get_headers())
        return response.json()

    def send_message(self, receiver_id: int, message: str, encrypted: bool = True):
        """Send a message"""
        url = f"{self.base_url}/api/messages/send"
        data = {
            "receiver_id": receiver_id,
            "content": message,
            "encrypted": encrypted
        }
        response = requests.post(url, json=data, headers=self.get_headers())
        return response.json()

    def get_chat(self, other_user_id: int, limit: int = 100):
        """Get chat messages"""
        url = f"{self.base_url}/api/messages/chat/{other_user_id}"
        params = {"limit": limit}
        response = requests.get(url, params=params, headers=self.get_headers())
        return response.json()

    def encode_stego(self, message: str, password: str):
        """Encode message in steganography"""
        url = f"{self.base_url}/api/stego/encode"
        data = {
            "operation": "encode",
            "message": message,
            "password": password,
            "method": "lsb",
            "intensity": 1
        }
        response = requests.post(url, json=data, headers=self.get_headers())
        return response.json()

    def decode_stego(self, password: str):
        """Decode message from steganography"""
        url = f"{self.base_url}/api/stego/decode"
        data = {
            "operation": "decode",
            "password": password,
            "method": "lsb",
            "intensity": 1
        }
        response = requests.post(url, json=data, headers=self.get_headers())
        return response.json()

    def get_stats(self):
        """Get user statistics"""
        url = f"{self.base_url}/api/stats/me"
        response = requests.get(url, headers=self.get_headers())
        return response.json()

    def upload_file(self, file_path: str, encrypted: bool = True, password: Optional[str] = None):
        """Upload a file"""
        url = f"{self.base_url}/api/files/upload"

        with open(file_path, 'rb') as f:
            file_data = base64.b64encode(f.read()).decode()

        data = {
            "filename": os.path.basename(file_path),
            "file_data": file_data,
            "encrypted": encrypted,
            "encryption_key": password
        }

        response = requests.post(url, json=data, headers=self.get_headers())
        return response.json()


# Example usage
if __name__ == "__main__":
    import os

    # Initialize client
    client = EEncryptClient()

    # Test login with existing user
    try:
        print("🔐 Logging in as alice...")
        result = client.login("alice", "password123")
        print(f"✅ Logged in as: {result['user']['username']}")

        # Get profile
        print("\n👤 Getting profile...")
        profile = client.get_profile()
        print(f"User ID: {profile['id']}")
        print(f"Status: {profile['status']}")
        print(f"Messages sent: {profile['stats']['messages_sent']}")

        # Get all users
        print("\n👥 Getting all users...")
        users = client.get_users()
        for user in users:
            print(f"• {user['username']} ({'🟢' if user['is_online'] else '⚫'})")

        # Send message to bob (ID 2)
        print("\n💬 Sending message to bob...")
        if len(users) > 0:
            bob = next((u for u in users if u['username'] == 'bob'), None)
            if bob:
                message = client.send_message(bob['id'], "Hello from Python client!")
                print(f"✅ Message sent with ID: {message['message_id']}")

        # Get chat with bob
        print("\n📨 Getting chat with bob...")
        if bob:
            chat = client.get_chat(bob['id'])
            print(f"Found {len(chat)} messages")
            for msg in chat[:3]:  # Show first 3 messages
                print(f"{'You' if msg['is_me'] else 'Them'}: {msg['content'][:50]}...")

        # Test steganography
        print("\n🖼️ Testing steganography encoding...")
        stego = client.encode_stego("Secret hidden message", "mypassword123")
        print(f"✅ Stego operation ID: {stego['operation_id']}")

        # Get statistics
        print("\n📊 Getting statistics...")
        stats = client.get_stats()
        print(f"Messages sent: {stats['messages']['sent']}")
        print(f"Stego operations: {stats['steganography']['operations']}")

    except Exception as e:
        print(f"❌ Error: {e}")