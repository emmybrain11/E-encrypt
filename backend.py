"""
🚀 E-Encrypt Backend - FastAPI Server with All Features
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import sqlite3
import hashlib
import base64
import os
import tempfile
import json
import uuid
from datetime import datetime
from typing import List, Optional
import asyncio
import uvicorn
from PIL import Image
import io
import numpy as np

# Import encryption
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

app = FastAPI(title="E-Encrypt Backend", version="1.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== DATABASE ====================
class Database:
    def __init__(self, db_path='encrypted_chat.db'):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                phone TEXT,
                profile_pic TEXT,
                status TEXT DEFAULT "Hey there! I'm using E-Encrypt",
                is_online BOOLEAN DEFAULT 0,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message_type TEXT DEFAULT 'text',
                content TEXT,
                media_url TEXT,
                is_encrypted BOOLEAN DEFAULT 0,
                encryption_key TEXT,
                status TEXT DEFAULT 'sent',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')

        # Files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT UNIQUE NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER,
                uploaded_by INTEGER,
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_encrypted BOOLEAN DEFAULT 0,
                FOREIGN KEY (uploaded_by) REFERENCES users(id)
            )
        ''')

        # Create default users if none exist
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            default_users = [
                ('alice', hashlib.sha256('password123'.encode()).hexdigest(), '+1234567890', 'Available', '#25D366'),
                ('bob', hashlib.sha256('password123'.encode()).hexdigest(), '+1234567891', 'At work', '#34B7F1'),
                ('charlie', hashlib.sha256('password123'.encode()).hexdigest(), '+1234567892', 'Sleeping', '#FF6B6B'),
                ('david', hashlib.sha256('password123'.encode()).hexdigest(), '+1234567893', 'Vacation', '#FFD93D'),
                ('emma', hashlib.sha256('password123'.encode()).hexdigest(), '+1234567894', 'Busy', '#9B59B6')
            ]

            for username, pwd_hash, phone, status, color in default_users:
                cursor.execute('''
                    INSERT INTO users (username, password_hash, phone, status, is_online, last_seen)
                    VALUES (?, ?, ?, ?, 1, ?)
                ''', (username, pwd_hash, phone, status, datetime.now()))

        conn.commit()
        conn.close()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    # User operations
    def create_user(self, username, password, phone=None):
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return None

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        cursor.execute('''
            INSERT INTO users (username, password_hash, phone, is_online, last_seen)
            VALUES (?, ?, ?, 1, ?)
        ''', (username, password_hash, phone, datetime.now()))

        user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return user_id

    def authenticate_user(self, username, password):
        conn = self.get_connection()
        cursor = conn.cursor()

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        cursor.execute('''
            SELECT id, username, phone, profile_pic, status, is_online
            FROM users 
            WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))

        user = cursor.fetchone()
        if user:
            cursor.execute('UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?',
                           (datetime.now(), user[0]))
            conn.commit()

        conn.close()

        if user:
            return {
                'id': user[0],
                'username': user[1],
                'phone': user[2],
                'profile_pic': user[3],
                'status': user[4],
                'is_online': bool(user[5])
            }
        return None

    def get_users(self):
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, username, phone, profile_pic, status, is_online, last_seen
            FROM users
            ORDER BY is_online DESC, username ASC
        ''')

        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'phone': row[2],
                'profile_pic': row[3],
                'status': row[4],
                'is_online': bool(row[5]),
                'last_seen': row[6]
            })

        conn.close()
        return users

    # Message operations
    def save_message(self, chat_id, sender_id, receiver_id, content, message_type='text',
                     media_url=None, is_encrypted=False, encryption_key=None):
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO messages (chat_id, sender_id, receiver_id, message_type, 
                                content, media_url, is_encrypted, encryption_key, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (chat_id, sender_id, receiver_id, message_type, content, media_url,
              is_encrypted, encryption_key, datetime.now()))

        message_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return message_id

    def get_messages(self, chat_id, limit=50):
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT m.id, m.sender_id, m.receiver_id, m.message_type, m.content, 
                   m.media_url, m.is_encrypted, m.encryption_key, m.status, m.timestamp,
                   u.username as sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.chat_id = ?
            ORDER BY m.timestamp ASC
            LIMIT ?
        ''', (chat_id, limit))

        messages = []
        for row in cursor.fetchall():
            messages.append({
                'id': row[0],
                'sender_id': row[1],
                'receiver_id': row[2],
                'message_type': row[3],
                'content': row[4],
                'media_url': row[5],
                'is_encrypted': bool(row[6]),
                'encryption_key': row[7],
                'status': row[8],
                'timestamp': row[9],
                'sender_name': row[10]
            })

        conn.close()
        return messages


# Initialize database
db = Database()


# ==================== ENCRYPTION MANAGER ====================
class EncryptionManager:
    @staticmethod
    def encrypt_message(message: str, password: str) -> str:
        """Encrypt message using AES-256"""
        try:
            salt = get_random_bytes(16)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            padded_message = pad(message.encode('utf-8'), AES.block_size)
            encrypted = cipher.encrypt(padded_message)

            result = salt + iv + encrypted
            return base64.b64encode(result).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    @staticmethod
    def decrypt_message(encrypted_data: str, password: str) -> str:
        """Decrypt message using AES-256"""
        try:
            data = base64.b64decode(encrypted_data)
            salt = data[:16]
            iv = data[16:32]
            encrypted = data[32:]

            key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            original = unpad(decrypted, AES.block_size)

            return original.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    @staticmethod
    def encrypt_file(file_data: bytes, password: str) -> bytes:
        """Encrypt file data"""
        try:
            salt = get_random_bytes(16)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            padded_data = pad(file_data, AES.block_size)
            encrypted = cipher.encrypt(padded_data)

            return salt + iv + encrypted
        except Exception:
            return None

    @staticmethod
    def decrypt_file(encrypted_data: bytes, password: str) -> bytes:
        """Decrypt file data"""
        try:
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            encrypted = encrypted_data[32:]

            key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            original = unpad(decrypted, AES.block_size)

            return original
        except Exception:
            return None


# ==================== STEGANOGRAPHY MANAGER ====================
class SteganographyManager:
    @staticmethod
    def encode_message(image_bytes: bytes, message: str, password: str) -> bytes:
        """Encode message into image"""
        try:
            encrypted_msg = EncryptionManager.encrypt_message(message, password)
            if not encrypted_msg:
                return None

            img = Image.open(io.BytesIO(image_bytes))
            if img.mode != 'RGB':
                img = img.convert('RGB')

            binary_data = ''.join(format(ord(char), '08b') for char in encrypted_msg)
            binary_data += '1111111111111110'

            pixels = list(img.getdata())
            width, height = img.size

            if len(binary_data) > len(pixels) * 3:
                return None

            data_index = 0
            new_pixels = []

            for pixel in pixels:
                r, g, b = pixel

                if data_index < len(binary_data):
                    r = (r & ~1) | int(binary_data[data_index])
                    data_index += 1

                if data_index < len(binary_data):
                    g = (g & ~1) | int(binary_data[data_index])
                    data_index += 1

                if data_index < len(binary_data):
                    b = (b & ~1) | int(binary_data[data_index])
                    data_index += 1

                new_pixels.append((r, g, b))

            stego_img = Image.new('RGB', (width, height))
            stego_img.putdata(new_pixels)

            buffer = io.BytesIO()
            stego_img.save(buffer, format='PNG')
            return buffer.getvalue()

        except Exception as e:
            print(f"Steganography encode error: {e}")
            return None

    @staticmethod
    def decode_message(image_bytes: bytes, password: str) -> str:
        """Decode message from image"""
        try:
            img = Image.open(io.BytesIO(image_bytes))
            if img.mode != 'RGB':
                img = img.convert('RGB')

            pixels = list(img.getdata())
            binary_data = ""

            for pixel in pixels:
                r, g, b = pixel
                binary_data += str(r & 1)
                binary_data += str(g & 1)
                binary_data += str(b & 1)

            delimiter = '1111111111111110'
            if delimiter not in binary_data:
                return None

            data_binary = binary_data[:binary_data.index(delimiter)]

            encrypted_data = ""
            for i in range(0, len(data_binary), 8):
                byte = data_binary[i:i + 8]
                if len(byte) == 8:
                    encrypted_data += chr(int(byte, 2))

            return EncryptionManager.decrypt_message(encrypted_data, password)

        except Exception as e:
            print(f"Steganography decode error: {e}")
            return None


# ==================== MODELS ====================
class UserCreate(BaseModel):
    username: str
    password: str
    phone: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class MessageSend(BaseModel):
    chat_id: str
    receiver_id: int
    content: str
    is_encrypted: bool = False
    password: Optional[str] = None


# ==================== API ENDPOINTS ====================
@app.get("/")
async def root():
    return {"message": "E-Encrypt Backend API", "status": "online"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# User endpoints
@app.post("/api/register")
async def register(user: UserCreate):
    user_id = db.create_user(user.username, user.password, user.phone)
    if user_id:
        return {"success": True, "user_id": user_id, "message": "User created successfully"}
    return {"success": False, "error": "Username already exists"}


@app.post("/api/login")
async def login(user: UserLogin):
    auth_user = db.authenticate_user(user.username, user.password)
    if auth_user:
        return {"success": True, "user": auth_user}
    return {"success": False, "error": "Invalid credentials"}


@app.get("/api/users")
async def get_all_users():
    users = db.get_users()
    return {"success": True, "users": users}


# Message endpoints
@app.post("/api/messages/send")
async def send_message(message: MessageSend, sender_id: int = Form(...)):
    user_ids = sorted([sender_id, message.receiver_id])
    chat_id = f"{user_ids[0]}_{user_ids[1]}"

    content = message.content
    encryption_key = None
    if message.is_encrypted and message.password:
        encrypted = EncryptionManager.encrypt_message(message.content, message.password)
        if encrypted:
            content = encrypted
            encryption_key = message.password

    message_id = db.save_message(
        chat_id=chat_id,
        sender_id=sender_id,
        receiver_id=message.receiver_id,
        content=content,
        is_encrypted=message.is_encrypted,
        encryption_key=encryption_key
    )

    return {"success": True, "message_id": message_id, "chat_id": chat_id}


@app.get("/api/messages/{chat_id}")
async def get_chat_messages(chat_id: str):
    messages = db.get_messages(chat_id)
    return {"success": True, "messages": messages}


# Encryption endpoints
@app.post("/api/encrypt")
async def encrypt(data: dict):
    encrypted = EncryptionManager.encrypt_message(data.get('message', ''), data.get('password', ''))
    if encrypted:
        return {"success": True, "encrypted_data": encrypted}
    return {"success": False, "error": "Encryption failed"}


@app.post("/api/decrypt")
async def decrypt(data: dict):
    decrypted = EncryptionManager.decrypt_message(data.get('encrypted_data', ''), data.get('password', ''))
    if decrypted:
        return {"success": True, "decrypted_data": decrypted}
    return {"success": False, "error": "Decryption failed"}


# File upload endpoint
@app.post("/api/files/upload")
async def upload_file(
        file: UploadFile = File(...),
        user_id: int = Form(...),
        encrypt: bool = Form(False),
        password: str = Form(None)
):
    try:
        file_data = await file.read()
        file_id = str(uuid.uuid4())

        is_encrypted = False
        if encrypt and password:
            encrypted_data = EncryptionManager.encrypt_file(file_data, password)
            if encrypted_data:
                file_data = encrypted_data
                is_encrypted = True

        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)

        stored_name = f"{file_id}_{file.filename}"
        file_path = os.path.join(upload_dir, stored_name)

        with open(file_path, "wb") as f:
            f.write(file_data)

        return {
            "success": True,
            "file_id": file_id,
            "original_name": file.filename,
            "file_size": len(file_data),
            "is_encrypted": is_encrypted
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# Steganography endpoints
@app.post("/api/steganography/encode")
async def encode_stego(
        image: UploadFile = File(...),
        message: str = Form(...),
        password: str = Form(...)
):
    try:
        image_data = await image.read()

        stego_data = SteganographyManager.encode_message(image_data, message, password)
        if not stego_data:
            return {"success": False, "error": "Encoding failed"}

        stego_b64 = base64.b64encode(stego_data).decode()

        return {
            "success": True,
            "stego_image": stego_b64,
            "message": "Message encoded successfully"
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/steganography/decode")
async def decode_stego(
        image: UploadFile = File(...),
        password: str = Form(...)
):
    try:
        image_data = await image.read()

        decoded = SteganographyManager.decode_message(image_data, password)
        if decoded:
            return {"success": True, "decoded_message": decoded}
        return {"success": False, "error": "Decoding failed or wrong password"}

    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)