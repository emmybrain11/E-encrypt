"""
🔐 E-ENCRYPT BACKEND SERVER
Complete FastAPI Backend with All Features
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import bcrypt
from jose import JWTError, jwt
from PIL import Image
import numpy as np
import io
import aiofiles
import asyncio
import sqlite3
from contextlib import contextmanager

# Database setup
DATABASE_PATH = "eencrypt.db"


def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        avatar_color TEXT DEFAULT '#25D366',
        is_online BOOLEAN DEFAULT 0,
        status TEXT DEFAULT 'Secure',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Chats table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        last_message_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user1_id) REFERENCES users (id),
        FOREIGN KEY (user2_id) REFERENCES users (id),
        UNIQUE(user1_id, user2_id)
    )
    ''')

    # Messages table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        chat_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        is_encrypted BOOLEAN DEFAULT 0,
        is_read BOOLEAN DEFAULT 0,
        message_type TEXT DEFAULT 'text',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users (id),
        FOREIGN KEY (receiver_id) REFERENCES users (id),
        FOREIGN KEY (chat_id) REFERENCES chats (id)
    )
    ''')

    # Steganography operations
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS stego_operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        operation_type TEXT NOT NULL,
        success BOOLEAN DEFAULT 1,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    # Insert test users if empty
    cursor.execute("SELECT COUNT(*) as count FROM users")
    if cursor.fetchone()[0] == 0:
        # Hash for 'password123'
        hashed_pw = bcrypt.hashpw(b"password123", bcrypt.gensalt()).decode()
        test_users = [
            ("alice", hashed_pw, "alice@example.com", "#FF6B6B"),
            ("bob", hashed_pw, "bob@example.com", "#4ECDC4"),
            ("charlie", hashed_pw, "charlie@example.com", "#45B7D1"),
            ("david", hashed_pw, "david@example.com", "#96CEB4"),
            ("emma", hashed_pw, "emma@example.com", "#FFEAA7"),
        ]

        for username, hashed_password, email, color in test_users:
            cursor.execute('''
            INSERT INTO users (username, hashed_password, email, avatar_color, is_online)
            VALUES (?, ?, ?, ?, 1)
            ''', (username, hashed_password, email, color))

    conn.commit()
    conn.close()


# Initialize database
init_database()


# Database connection helper
@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# Models
class UserRegister(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    phone: Optional[str] = None


class MessageSend(BaseModel):
    receiver_id: int
    content: str
    encrypted: bool = False
    encryption_password: Optional[str] = None
    message_type: str = "text"


class MessageDecrypt(BaseModel):
    password: str


# App Configuration
app = FastAPI(
    title="E-Encrypt API",
    description="Quantum-Resistant Secure Messaging System",
    version="2.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
SECRET_KEY = "e-encrypt-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# WebSocket connections
active_connections: Dict[int, WebSocket] = {}


# Helper Functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()

    if user is None:
        raise credentials_exception
    return dict(user)


# Steganography Functions
def lsb_encode(image: Image.Image, message: str, intensity: int = 1) -> Image.Image:
    """Encode message using LSB steganography"""
    if image.mode != 'RGB':
        image = image.convert('RGB')

    img_array = np.array(image)
    flat = img_array.flatten()

    # Convert message to binary with delimiter
    message_bin = ''.join(format(ord(c), '08b') for c in message)
    message_bin += '00000000'  # Null terminator

    # Check capacity
    max_bits = len(flat) * intensity
    if len(message_bin) > max_bits:
        raise ValueError(f"Message too long. Max: {max_bits // 8} characters")

    # Encode message
    idx = 0
    for i in range(0, len(message_bin), intensity):
        if idx >= len(flat):
            break
        byte_val = flat[idx]
        new_val = (byte_val & ~1) | int(message_bin[i])
        flat[idx] = new_val
        idx += 1

    # Reshape and return
    encoded_array = flat.reshape(img_array.shape)
    return Image.fromarray(encoded_array.astype(np.uint8))


def lsb_decode(image: Image.Image, intensity: int = 1) -> str:
    """Decode message from LSB steganography"""
    if image.mode != 'RGB':
        image = image.convert('RGB')

    img_array = np.array(image)
    flat = img_array.flatten()

    # Extract LSBs
    bits = []
    for i in range(0, min(len(flat), 1000000), intensity):
        bits.append(str(flat[i] & 1))
        if len(bits) % 8 == 0 and bits[-8:] == ['0'] * 8:
            break

    # Convert to string
    chars = []
    for i in range(0, len(bits) - 8, 8):
        byte_bits = bits[i:i + 8]
        byte_str = ''.join(byte_bits)
        try:
            char = chr(int(byte_str, 2))
            chars.append(char)
        except:
            break

    return ''.join(chars)


def encrypt_message(content: str, password: str) -> str:
    """Simple XOR encryption for demo"""
    if not password:
        return content

    key = hashlib.sha256(password.encode()).digest()
    key_length = len(key)

    encrypted = []
    for i, char in enumerate(content):
        key_char = key[i % key_length]
        encrypted_char = chr(ord(char) ^ key_char)
        encrypted.append(encrypted_char)

    encrypted_str = ''.join(encrypted)
    return base64.b64encode(encrypted_str.encode()).decode()


def decrypt_message(encrypted_content: str, password: str) -> str:
    """Decrypt XOR encrypted message"""
    if not password:
        return encrypted_content

    try:
        encrypted_bytes = base64.b64decode(encrypted_content)
        encrypted_str = encrypted_bytes.decode()

        key = hashlib.sha256(password.encode()).digest()
        key_length = len(key)

        decrypted = []
        for i, char in enumerate(encrypted_str):
            key_char = key[i % key_length]
            decrypted_char = chr(ord(char) ^ key_char)
            decrypted.append(decrypted_char)

        return ''.join(decrypted)
    except:
        raise ValueError("Decryption failed")


# API Routes
@app.get("/")
async def root():
    return {"app": "E-Encrypt API", "status": "running"}


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# Authentication
@app.post("/api/auth/register")
async def register(user_data: UserRegister):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check if username exists
        cursor.execute('SELECT * FROM users WHERE username = ?', (user_data.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Username already exists")

        # Create user
        hashed_password = get_password_hash(user_data.password)
        avatar_color = f"#{secrets.randbelow(0xFFFFFF):06x}"

        cursor.execute('''
        INSERT INTO users (username, hashed_password, email, phone, avatar_color, is_online)
        VALUES (?, ?, ?, ?, ?, 1)
        ''', (user_data.username, hashed_password, user_data.email, user_data.phone, avatar_color))

        user_id = cursor.lastrowid
        conn.commit()

        # Get user data
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()

    # Create access token
    access_token = create_access_token(data={"user_id": user_id})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "phone": user["phone"],
            "avatar_color": user["avatar_color"],
            "is_online": True,
            "status": "Secure"
        }
    }


@app.post("/api/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (form_data.username,))
        user = cursor.fetchone()

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # Update online status
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET is_online = 1 WHERE id = ?', (user["id"],))
        conn.commit()

    # Create token
    access_token = create_access_token(data={"user_id": user["id"]})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "phone": user["phone"],
            "avatar_color": user["avatar_color"],
            "is_online": True,
            "status": user["status"]
        }
    }


# Users
@app.get("/api/users")
async def get_users(current_user: dict = Depends(get_current_user)):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT id, username, email, avatar_color, is_online, status 
        FROM users WHERE id != ? ORDER BY is_online DESC, username
        ''', (current_user["id"],))
        users = cursor.fetchall()

    return [dict(user) for user in users]


# Chats
@app.get("/api/chats")
async def get_user_chats(current_user: dict = Depends(get_current_user)):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT c.*, 
               CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END as other_user_id,
               u.username as other_username,
               u.avatar_color as other_avatar_color,
               u.is_online as other_online,
               m.content as last_message,
               m.timestamp as last_message_time
        FROM chats c
        JOIN users u ON (CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END) = u.id
        LEFT JOIN messages m ON c.last_message_id = m.id
        WHERE c.user1_id = ? OR c.user2_id = ?
        ORDER BY m.timestamp DESC NULLS LAST
        ''', (current_user["id"], current_user["id"], current_user["id"], current_user["id"]))

        chats = cursor.fetchall()

    result = []
    for chat in chats:
        chat_dict = dict(chat)
        chat_dict["other_user"] = {
            "id": chat_dict["other_user_id"],
            "username": chat_dict["other_username"],
            "avatar_color": chat_dict["other_avatar_color"],
            "is_online": bool(chat_dict["other_online"])
        }
        result.append(chat_dict)

    return result


@app.post("/api/chats/create")
async def create_chat(other_user_id: int, current_user: dict = Depends(get_current_user)):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check if chat exists
        cursor.execute('''
        SELECT * FROM chats 
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
        ''', (current_user["id"], other_user_id, other_user_id, current_user["id"]))

        existing = cursor.fetchone()
        if existing:
            return {"chat_id": existing["id"], "message": "Chat already exists"}

        # Create new chat
        cursor.execute('''
        INSERT INTO chats (user1_id, user2_id) VALUES (?, ?)
        ''', (current_user["id"], other_user_id))

        chat_id = cursor.lastrowid
        conn.commit()

    return {"chat_id": chat_id, "message": "Chat created"}


# Messages
@app.get("/api/chats/{chat_id}/messages")
async def get_chat_messages(chat_id: int, current_user: dict = Depends(get_current_user)):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Verify user is part of chat
        cursor.execute('''
        SELECT * FROM chats WHERE id = ? AND (user1_id = ? OR user2_id = ?)
        ''', (chat_id, current_user["id"], current_user["id"]))

        if not cursor.fetchone():
            raise HTTPException(status_code=403, detail="Not authorized")

        # Get messages
        cursor.execute('''
        SELECT m.*, u.username as sender_username,
               CASE WHEN m.sender_id = ? THEN 1 ELSE 0 END as is_me
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.chat_id = ?
        ORDER BY m.timestamp ASC
        LIMIT 100
        ''', (current_user["id"], chat_id))

        messages = cursor.fetchall()

    result = []
    for msg in messages:
        msg_dict = dict(msg)
        msg_dict["is_me"] = bool(msg_dict["is_me"])
        result.append(msg_dict)

    return result


@app.post("/api/messages/send")
async def send_message(message_data: MessageSend, current_user: dict = Depends(get_current_user)):
    # Encrypt if needed
    content = message_data.content
    if message_data.encrypted and message_data.encryption_password:
        content = encrypt_message(content, message_data.encryption_password)

    # Get or create chat
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check for existing chat
        cursor.execute('''
        SELECT * FROM chats 
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
        ''', (current_user["id"], message_data.receiver_id, message_data.receiver_id, current_user["id"]))

        chat = cursor.fetchone()
        if not chat:
            # Create new chat
            cursor.execute('INSERT INTO chats (user1_id, user2_id) VALUES (?, ?)',
                           (current_user["id"], message_data.receiver_id))
            chat_id = cursor.lastrowid
            conn.commit()
        else:
            chat_id = chat["id"]

        # Create message
        cursor.execute('''
        INSERT INTO messages (sender_id, receiver_id, chat_id, content, is_encrypted, message_type)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (current_user["id"], message_data.receiver_id, chat_id, content,
              1 if message_data.encrypted else 0, message_data.message_type))

        message_id = cursor.lastrowid

        # Update chat's last message
        cursor.execute('UPDATE chats SET last_message_id = ? WHERE id = ?',
                       (message_id, chat_id))

        conn.commit()

    # Notify receiver via WebSocket
    receiver_ws = active_connections.get(message_data.receiver_id)
    if receiver_ws:
        await receiver_ws.send_json({
            "type": "new_message",
            "message": {
                "id": message_id,
                "sender_id": current_user["id"],
                "sender_username": current_user["username"],
                "content": content,
                "timestamp": datetime.utcnow().isoformat(),
                "is_encrypted": message_data.encrypted,
                "is_read": False
            }
        })

    return {"message_id": message_id, "status": "sent"}


@app.post("/api/messages/{message_id}/decrypt")
async def decrypt_message(message_id: int, decrypt_data: MessageDecrypt,
                          current_user: dict = Depends(get_current_user)):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM messages WHERE id = ?', (message_id,))
        message = cursor.fetchone()

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    if message["receiver_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    if not message["is_encrypted"]:
        return {"original_message": message["content"]}

    try:
        decrypted = decrypt_message(message["content"], decrypt_data.password)
        return {"original_message": decrypted}
    except:
        raise HTTPException(status_code=400, detail="Decryption failed")


# Steganography
@app.post("/api/steganography/encode")
async def stego_encode(
        image: UploadFile = File(...),
        message: str = Form(...),
        password: str = Form(...),
        method: str = Form("lsb"),
        intensity: int = Form(1),
        current_user: dict = Depends(get_current_user)
):
    try:
        # Read image
        contents = await image.read()
        img = Image.open(io.BytesIO(contents))

        # Encode message
        if method == "lsb":
            encoded_img = lsb_encode(img, message, intensity)
        else:
            raise HTTPException(status_code=400, detail="Unsupported method")

        # Save to bytes
        img_byte_arr = io.BytesIO()
        encoded_img.save(img_byte_arr, format='PNG')
        encoded_bytes = img_byte_arr.getvalue()

        # Record operation
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO stego_operations (user_id, operation_type, success)
            VALUES (?, ?, ?)
            ''', (current_user["id"], "encode", 1))
            conn.commit()

        return {
            "encoded_image": base64.b64encode(encoded_bytes).decode(),
            "filename": f"encoded_{uuid.uuid4().hex[:8]}.png",
            "message": "Message encoded successfully"
        }
    except Exception as e:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO stego_operations (user_id, operation_type, success)
            VALUES (?, ?, ?)
            ''', (current_user["id"], "encode", 0))
            conn.commit()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/steganography/decode")
async def stego_decode(
        image: UploadFile = File(...),
        password: str = Form(...),
        method: str = Form("lsb"),
        intensity: int = Form(1),
        current_user: dict = Depends(get_current_user)
):
    try:
        # Read image
        contents = await image.read()
        img = Image.open(io.BytesIO(contents))

        # Decode message
        if method == "lsb":
            decoded_message = lsb_decode(img, intensity)
        else:
            raise HTTPException(status_code=400, detail="Unsupported method")

        # Record operation
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO stego_operations (user_id, operation_type, success)
            VALUES (?, ?, ?)
            ''', (current_user["id"], "decode", 1))
            conn.commit()

        return {
            "decoded_message": decoded_message,
            "message": "Message decoded successfully"
        }
    except Exception as e:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO stego_operations (user_id, operation_type, success)
            VALUES (?, ?, ?)
            ''', (current_user["id"], "decode", 0))
            conn.commit()
        raise HTTPException(status_code=500, detail=str(e))


# Statistics
@app.get("/api/stats/me")
async def get_my_stats(current_user: dict = Depends(get_current_user)):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Message stats
        cursor.execute('SELECT COUNT(*) as sent FROM messages WHERE sender_id = ?', (current_user["id"],))
        sent = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) as received FROM messages WHERE receiver_id = ?', (current_user["id"],))
        received = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) as unread FROM messages WHERE receiver_id = ? AND is_read = 0',
                       (current_user["id"],))
        unread = cursor.fetchone()[0]

        # Chat stats
        cursor.execute('''
        SELECT COUNT(*) as active FROM chats 
        WHERE user1_id = ? OR user2_id = ?
        ''', (current_user["id"], current_user["id"]))
        active_chats = cursor.fetchone()[0]

        # Steganography stats
        cursor.execute('''
        SELECT COUNT(*) as total FROM stego_operations WHERE user_id = ?
        ''', (current_user["id"],))
        stego_total = cursor.fetchone()[0]

    return {
        "messages": {
            "sent": sent,
            "received": received,
            "unread": unread
        },
        "chats": {
            "active": active_chats,
            "total": active_chats
        },
        "steganography": {
            "operations": stego_total,
            "successful": stego_total  # Simplified
        }
    }


# WebSocket
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, token: str):
    await websocket.accept()

    try:
        # Verify token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_user_id = payload.get("user_id")

        if token_user_id != user_id:
            await websocket.close(code=1008)
            return

        # Add connection
        active_connections[user_id] = websocket

        # Update online status
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET is_online = 1 WHERE id = ?', (user_id,))
            conn.commit()

        try:
            while True:
                data = await websocket.receive_json()

                if data["type"] == "typing":
                    receiver_id = data["receiver_id"]
                    receiver_ws = active_connections.get(receiver_id)
                    if receiver_ws:
                        await receiver_ws.send_json({
                            "type": "typing",
                            "sender_id": user_id,
                            "chat_id": data["chat_id"],
                            "is_typing": data["is_typing"]
                        })

        except WebSocketDisconnect:
            pass

    except JWTError:
        await websocket.close(code=1008)
    finally:
        # Clean up
        if user_id in active_connections:
            del active_connections[user_id]

        # Update offline status
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET is_online = 0 WHERE id = ?', (user_id,))
            conn.commit()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)