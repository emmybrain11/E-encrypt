"""
📦 E-Encrypt Complete Installation Script
Run: python install_all.py
"""

import subprocess
import sys
import os
import platform


def print_header():
    print("=" * 60)
    print("🔐 E-Encrypt Complete System Installation")
    print("=" * 60)
    print()


def check_python_version():
    """Check Python version"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 or higher is required")
        print(f"   You have Python {version.major}.{version.minor}.{version.micro}")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} detected")
    return True


def create_virtual_env():
    """Create virtual environment"""
    if not os.path.exists("venv"):
        print("📦 Creating virtual environment...")
        try:
            subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
            print("✅ Virtual environment created")
            return True
        except:
            print("⚠️  Failed to create virtual environment")
            print("   Continuing with global installation...")
            return True
    else:
        print("✅ Virtual environment already exists")
        return True


def get_pip_path():
    """Get pip path based on platform"""
    if os.path.exists("venv"):
        if platform.system() == "Windows":
            return "venv\\Scripts\\pip"
        else:
            return "venv/bin/pip"
    else:
        return sys.executable.replace("python", "pip")


def get_python_path():
    """Get python path based on platform"""
    if os.path.exists("venv"):
        if platform.system() == "Windows":
            return "venv\\Scripts\\python"
        else:
            return "venv/bin/python"
    else:
        return sys.executable


def install_packages():
    """Install all required packages"""
    print("\n📦 Installing dependencies...")

    # Upgrade pip first
    print("  1. Upgrading pip...")
    pip_path = get_pip_path()
    subprocess.run([pip_path, "install", "--upgrade", "pip"], check=False)

    # Backend packages
    backend_packages = [
        "fastapi==0.104.0",
        "uvicorn[standard]==0.24.0",
        "sqlalchemy==2.0.23",
        "pycryptodome==3.19.0",
        "PyJWT==2.8.0",
        "python-multipart==0.0.6",
        "requests==2.31.0"
    ]

    print("  2. Installing backend packages...")
    for package in backend_packages:
        print(f"     Installing {package}...")
        subprocess.run([pip_path, "install", package], check=False)

    # Web app packages
    web_packages = [
        "streamlit==1.28.0",
        "pillow==10.0.0"
    ]

    print("  3. Installing web app packages...")
    for package in web_packages:
        print(f"     Installing {package}...")
        subprocess.run([pip_path, "install", package], check=False)

    # Desktop app packages
    desktop_packages = [
        "kivy==2.3.0",
        "pillow==10.0.0",  # Already installed, but safe to include
        "websocket-client==1.6.4"
    ]

    print("  4. Installing desktop app packages...")
    for package in desktop_packages:
        print(f"     Installing {package}...")
        try:
            subprocess.run([pip_path, "install", package], check=False)
        except:
            print(f"     ⚠️  Could not install {package}, skipping...")

    print("✅ All packages installed!")


def create_required_files():
    """Create required files if they don't exist"""
    print("\n📄 Creating required files...")

    # Create each file individually to avoid syntax issues
    files_content = {
        "backend_api.py": """from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import hashlib
import jwt
import base64
import os
import json
from pydantic import BaseModel
import uvicorn
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# JWT Configuration
SECRET_KEY = "e-encrypt-secret-key-2024-quantum-secure"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
DATABASE_URL = "sqlite:///./eencrypt.db"

# Database setup
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    email = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    avatar_color = Column(String, default="#25D366")
    status = Column(String, default="Secure & Encrypted 🔐")
    is_online = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=datetime.utcnow())
    created_at = Column(DateTime, default=datetime.utcnow())

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    chat_id = Column(String, index=True)
    content = Column(Text)
    encrypted = Column(Boolean, default=False)
    encryption_key = Column(Text, nullable=True)
    message_type = Column(String, default="text")
    read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow())

# Create database
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Pydantic models
class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    phone: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class MessageCreate(BaseModel):
    receiver_id: int
    content: str
    encrypted: bool = False
    encryption_key: Optional[str] = None

# FastAPI app
app = FastAPI(title="E-Encrypt Backend", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

class AESEncryption:
    @staticmethod
    def encrypt_message(message: str, password: str) -> str:
        try:
            salt = get_random_bytes(16)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_message = pad(message.encode('utf-8'), AES.block_size)
            encrypted = cipher.encrypt(padded_message)
            result = salt + iv + encrypted
            return base64.b64encode(result).decode('utf-8')
        except:
            return None

    @staticmethod
    def decrypt_message(encrypted_data: str, password: str) -> str:
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
        except:
            return None

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, message: str, user_id: int):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_text(message)

manager = ConnectionManager()

def create_test_users(db: Session):
    test_users = [
        {'username': 'alice', 'password': 'password123', 'email': 'alice@eencrypt.com'},
        {'username': 'bob', 'password': 'password123', 'email': 'bob@eencrypt.com'},
        {'username': 'charlie', 'password': 'password123', 'email': 'charlie@eencrypt.com'},
        {'username': 'david', 'password': 'password123', 'email': 'david@eencrypt.com'},
        {'username': 'emma', 'password': 'password123', 'email': 'emma@eencrypt.com'},
    ]

    for user_data in test_users:
        existing = db.query(User).filter(User.username == user_data['username']).first()
        if not existing:
            user = User(
                username=user_data['username'],
                password_hash=hash_password(user_data['password']),
                email=user_data['email'],
                is_online=True
            )
            db.add(user)

    db.commit()

@app.on_event("startup")
async def startup_event():
    db = SessionLocal()
    create_test_users(db)
    db.close()
    print("✅ Backend started with test users!")

@app.get("/")
async def root():
    return {
        "app": "E-Encrypt Backend",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.post("/api/auth/register")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = User(
        username=user.username,
        password_hash=hash_password(user.password),
        email=user.email,
        phone=user.phone,
        is_online=True
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    access_token = create_access_token(
        data={"sub": str(new_user.id), "username": new_user.username}
    )

    return {
        "message": "User registered",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "phone": new_user.phone,
            "is_online": new_user.is_online
        }
    }

@app.post("/api/auth/login")
async def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    db_user.is_online = True
    db_user.last_seen = datetime.utcnow()
    db.commit()

    access_token = create_access_token(
        data={"sub": str(db_user.id), "username": db_user.username}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email,
            "phone": db_user.phone,
            "status": db_user.status,
            "avatar_color": db_user.avatar_color,
            "is_online": db_user.is_online
        }
    }

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = int(payload.get("sub"))
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user

@app.get("/api/users/me")
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "phone": current_user.phone,
        "status": current_user.status,
        "avatar_color": current_user.avatar_color,
        "is_online": current_user.is_online,
        "last_seen": current_user.last_seen
    }

@app.get("/api/users")
async def get_all_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    users = db.query(User).filter(User.id != current_user.id).all()
    return [
        {
            "id": user.id,
            "username": user.username,
            "status": user.status,
            "avatar_color": user.avatar_color,
            "is_online": user.is_online
        }
        for user in users
    ]

@app.post("/api/messages/send")
async def send_message(
    message: MessageCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    receiver = db.query(User).filter(User.id == message.receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")

    chat_id = f"{min(current_user.id, message.receiver_id)}:{max(current_user.id, message.receiver_id)}"

    content = message.content
    if message.encrypted and message.encryption_key:
        content = AESEncryption.encrypt_message(message.content, message.encryption_key)
        if not content:
            raise HTTPException(status_code=500, detail="Encryption failed")

    db_message = Message(
        sender_id=current_user.id,
        receiver_id=message.receiver_id,
        chat_id=chat_id,
        content=content,
        encrypted=message.encrypted,
        encryption_key=message.encryption_key,
        timestamp=datetime.utcnow()
    )

    db.add(db_message)
    db.commit()
    db.refresh(db_message)

    notification = {
        "type": "new_message",
        "message_id": db_message.id,
        "sender_id": current_user.id,
        "sender_username": current_user.username,
        "content": "🔒 Encrypted message" if message.encrypted else message.content,
        "encrypted": message.encrypted,
        "timestamp": db_message.timestamp.isoformat()
    }

    try:
        await manager.send_personal_message(json.dumps(notification), message.receiver_id)
    except:
        pass

    return {
        "message": "Message sent",
        "message_id": db_message.id,
        "chat_id": chat_id
    }

@app.get("/api/messages/chat/{other_user_id}")
async def get_chat_messages(
    other_user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    chat_id = f"{min(current_user.id, other_user_id)}:{max(current_user.id, other_user_id)}"

    messages = db.query(Message).filter(
        Message.chat_id == chat_id
    ).order_by(Message.timestamp.asc()).all()

    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.read:
            msg.read = True

    db.commit()

    return [
        {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "receiver_id": msg.receiver_id,
            "content": msg.content,
            "encrypted": msg.encrypted,
            "read": msg.read,
            "timestamp": msg.timestamp.isoformat(),
            "is_me": msg.sender_id == current_user.id
        }
        for msg in messages
    ]

@app.get("/api/messages/chats")
async def get_user_chats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sent_to = db.query(Message.receiver_id).filter(Message.sender_id == current_user.id).distinct()
    received_from = db.query(Message.sender_id).filter(Message.receiver_id == current_user.id).distinct()

    user_ids = set([id[0] for id in sent_to] + [id[0] for id in received_from])

    chats = []
    for user_id in user_ids:
        if user_id == current_user.id:
            continue

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            continue

        last_message = db.query(Message).filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()

        unread_count = db.query(Message).filter(
            Message.sender_id == user_id,
            Message.receiver_id == current_user.id,
            Message.read == False
        ).count()

        chats.append({
            "chat_id": f"chat_{user_id}",
            "other_user": {
                "id": user.id,
                "username": user.username,
                "status": user.status,
                "avatar_color": user.avatar_color,
                "is_online": user.is_online
            },
            "last_message": {
                "content": last_message.content[:50] + "..." if last_message and len(last_message.content) > 50 else last_message.content if last_message else "No messages",
                "timestamp": last_message.timestamp if last_message else datetime.utcnow()
            } if last_message else None,
            "unread_count": unread_count,
            "updated_at": last_message.timestamp if last_message else datetime.utcnow()
        })

    chats.sort(key=lambda x: x['updated_at'], reverse=True)

    return chats

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, token: str):
    payload = verify_token(token)
    if not payload or int(payload.get("sub")) != int(user_id):
        await websocket.close()
        return

    await manager.connect(websocket, int(user_id))

    db = SessionLocal()
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user:
        user.is_online = True
        db.commit()

    try:
        while True:
            data = await websocket.receive_text()
            try:
                message_data = json.loads(data)
                if message_data.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except:
                pass
    except WebSocketDisconnect:
        manager.disconnect(int(user_id))
        db = SessionLocal()
        user = db.query(User).filter(User.id == int(user_id)).first()
        if user:
            user.is_online = False
            db.commit()
        db.close()

@app.get("/api/stats/me")
async def get_user_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    messages_sent = db.query(Message).filter(Message.sender_id == current_user.id).count()
    messages_received = db.query(Message).filter(Message.receiver_id == current_user.id).count()
    unread = db.query(Message).filter(
        Message.receiver_id == current_user.id,
        Message.read == False
    ).count()

    return {
        "messages": {
            "sent": messages_sent,
            "received": messages_received,
            "unread": unread
        },
        "chats": {
            "active": len(set(
                [m.receiver_id for m in db.query(Message).filter(Message.sender_id == current_user.id).all()] +
                [m.sender_id for m in db.query(Message).filter(Message.receiver_id == current_user.id).all()]
            ))
        }
    }

if __name__ == "__main__":
    print("🚀 E-Encrypt Backend Server")
    print("Starting on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
""",

        "main_web_backend.py": """import streamlit as st
import requests
import json
from datetime import datetime

BACKEND_URL = "http://localhost:8000"

class BackendClient:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.token = None
        self.user_id = None

    def login(self, username, password):
        url = f"{self.base_url}/api/auth/login"
        data = {"username": username, "password": password}
        try:
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                self.token = result["access_token"]
                self.user_id = result["user"]["id"]
                return {"success": True, "data": result}
            else:
                return {"success": False, "error": "Login failed"}
        except:
            return {"success": False, "error": "Cannot connect to backend"}

    def get_headers(self):
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def get_users(self):
        url = f"{self.base_url}/api/users"
        try:
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to get users"}
        except:
            return {"success": False, "error": "Connection failed"}

    def send_message(self, receiver_id, content):
        url = f"{self.base_url}/api/messages/send"
        data = {"receiver_id": receiver_id, "content": content}
        try:
            response = requests.post(url, json=data, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to send"}
        except:
            return {"success": False, "error": "Connection failed"}

    def get_chat_messages(self, other_user_id):
        url = f"{self.base_url}/api/messages/chat/{other_user_id}"
        try:
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to get chat"}
        except:
            return {"success": False, "error": "Connection failed"}

def main():
    st.set_page_config(page_title="E-Encrypt", page_icon="🔐", layout="wide")

    st.markdown(\"\"\"
    <style>
    .main-header {font-size: 2.5rem; color: #25D366; text-align: center;}
    .chat-bubble {padding: 10px; border-radius: 10px; margin: 5px;}
    </style>
    \"\"\", unsafe_allow_html=True)

    st.markdown('<h1 class="main-header">🔐 E-Encrypt</h1>', unsafe_allow_html=True)
    st.markdown("### Secure Messenger with Backend")

    if 'backend' not in st.session_state:
        st.session_state.backend = BackendClient()

    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        # Login page
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown("### Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            col1, col2 = st.columns(2)
            with col1:
                if st.button("Login", use_container_width=True):
                    if username and password:
                        result = st.session_state.backend.login(username, password)
                        if result['success']:
                            st.session_state.logged_in = True
                            st.session_state.user = result['data']['user']
                            st.rerun()
                        else:
                            st.error(f"Login failed: {result['error']}")
                    else:
                        st.error("Enter username and password")

            with col2:
                if st.button("Test Users", use_container_width=True):
                    st.info("Test users: alice, bob, charlie, david, emma")
                    st.info("Password: password123")
    else:
        # Main app
        user = st.session_state.user

        st.sidebar.markdown(f"### 👤 {user['username']}")
        st.sidebar.markdown(f"*{user.get('status', 'Online')}*")

        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.rerun()

        # Get all users
        result = st.session_state.backend.get_users()

        if not result['success']:
            st.error(f"Cannot load users: {result['error']}")
            return

        users = result['data']

        # Select a user to chat with
        user_options = [f"{u['username']} ({'🟢' if u['is_online'] else '⚫'})" for u in users]
        selected_user = st.selectbox("Select user to chat with", user_options)

        if selected_user:
            selected_username = selected_user.split(" ")[0]
            selected_user_data = next(u for u in users if u['username'] == selected_username)

            # Chat container
            chat_container = st.container(height=400)

            with chat_container:
                # Get chat messages
                chat_result = st.session_state.backend.get_chat_messages(selected_user_data['id'])

                if chat_result['success']:
                    messages = chat_result['data']

                    if not messages:
                        st.info(f"Start chatting with {selected_username}!")
                    else:
                        for msg in messages:
                            if msg['is_me']:
                                st.markdown(f\"\"\"
                                <div style='background-color: #25D366; color: white; padding: 10px; 
                                          border-radius: 10px 10px 0 10px; margin: 5px; margin-left: auto; 
                                          max-width: 70%;'>
                                    <strong>You</strong><br>
                                    {msg['content']}<br>
                                    <small>{msg['timestamp'][11:16] if 'timestamp' in msg else ''}</small>
                                </div>
                                \"\"\", unsafe_allow_html=True)
                            else:
                                st.markdown(f\"\"\"
                                <div style='background-color: #2A2F32; color: white; padding: 10px; 
                                          border-radius: 10px 10px 10px 0; margin: 5px; margin-right: auto; 
                                          max-width: 70%;'>
                                    <strong>{selected_username}</strong><br>
                                    {msg['content']}<br>
                                    <small>{msg['timestamp'][11:16] if 'timestamp' in msg else ''}</small>
                                </div>
                                \"\"\", unsafe_allow_html=True)
                else:
                    st.error(f"Cannot load chat: {chat_result['error']}")

            # Message input
            col1, col2 = st.columns([4, 1])
            with col1:
                new_message = st.text_input("Type message...", key="msg_input")

            with col2:
                if st.button("Send") and new_message:
                    send_result = st.session_state.backend.send_message(selected_user_data['id'], new_message)
                    if send_result['success']:
                        st.rerun()
                    else:
                        st.error(f"Failed to send: {send_result['error']}")

if __name__ == "__main__":
    main()
""",

        "main_desktop_backend.py": """import os
import sys
import json
import requests
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.core.window import Window
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock
from datetime import datetime
import threading

BACKEND_URL = "http://localhost:8000"

class BackendClient:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.token = None
        self.user_id = None

    def login(self, username, password):
        url = f"{self.base_url}/api/auth/login"
        data = {"username": username, "password": password}
        try:
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                self.token = result["access_token"]
                self.user_id = result["user"]["id"]
                return {"success": True, "data": result}
            else:
                return {"success": False, "error": "Login failed"}
        except:
            return {"success": False, "error": "Cannot connect to backend"}

    def get_headers(self):
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def get_users(self):
        url = f"{self.base_url}/api/users"
        try:
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to get users"}
        except:
            return {"success": False, "error": "Connection failed"}

    def send_message(self, receiver_id, content):
        url = f"{self.base_url}/api/messages/send"
        data = {"receiver_id": receiver_id, "content": content}
        try:
            response = requests.post(url, json=data, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to send"}
        except:
            return {"success": False, "error": "Connection failed"}

    def get_chat_messages(self, other_user_id):
        url = f"{self.base_url}/api/messages/chat/{other_user_id}"
        try:
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to get chat"}
        except:
            return {"success": False, "error": "Connection failed"}

class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        layout = BoxLayout(orientation='vertical', padding=50, spacing=20)

        logo = Label(text='🔐 E-Encrypt', font_size='48sp', color=(0.07, 0.55, 0.49, 1))
        layout.add_widget(logo)

        subtitle = Label(text='Secure Messenger with Backend', font_size='16sp', color=(0.5, 0.5, 0.5, 1))
        layout.add_widget(subtitle)

        layout.add_widget(Label(size_hint_y=None, height=30))

        self.username = TextInput(
            hint_text='Username',
            size_hint_y=None,
            height=50,
            multiline=False,
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1)
        )
        layout.add_widget(self.username)

        self.password = TextInput(
            hint_text='Password',
            password=True,
            size_hint_y=None,
            height=50,
            multiline=False,
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1)
        )
        layout.add_widget(self.password)

        login_btn = Button(
            text='Login',
            size_hint_y=None,
            height=50,
            background_color=(0.07, 0.55, 0.49, 1),
            color=(1, 1, 1, 1)
        )
        login_btn.bind(on_press=self.do_login)
        layout.add_widget(login_btn)

        test_btn = Button(
            text='Test Users',
            size_hint_y=None,
            height=50,
            background_color=(0.3, 0.5, 0.7, 1),
            color=(1, 1, 1, 1)
        )
        test_btn.bind(on_press=self.show_test_users)
        layout.add_widget(test_btn)

        self.status_label = Label(
            text='Backend: Not connected',
            size_hint_y=None,
            height=30,
            color=(1, 0.3, 0.3, 1)
        )
        layout.add_widget(self.status_label)

        self.add_widget(layout)

        Clock.schedule_once(lambda dt: self.test_connection(), 1)

    def test_connection(self):
        def test():
            try:
                response = requests.get(f"{BACKEND_URL}/api/health", timeout=5)
                if response.status_code == 200:
                    Clock.schedule_once(lambda dt: self.update_status('Backend: Connected', (0.3, 1, 0.3, 1)), 0)
            except:
                pass

        threading.Thread(target=test).start()

    def update_status(self, text, color):
        self.status_label.text = text
        self.status_label.color = color

    def do_login(self, instance):
        username = self.username.text.strip()
        password = self.password.text.strip()

        if not username or not password:
            self.show_popup('Error', 'Enter username and password')
            return

        app = App.get_running_app()
        result = app.backend.login(username, password)

        if result['success']:
            app.current_user = result['data']['user']
            app.sm.current = 'chats'
        else:
            self.show_popup('Login Failed', result['error'])

    def show_test_users(self, instance):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text='Test Users:', font_size='16sp'))
        content.add_widget(Label(text='• alice : password123', font_size='14sp'))
        content.add_widget(Label(text='• bob : password123', font_size='14sp'))
        content.add_widget(Label(text='• charlie : password123', font_size='14sp'))
        content.add_widget(Label(text='• david : password123', font_size='14sp'))
        content.add_widget(Label(text='• emma : password123', font_size='14sp'))

        btn = Button(text='OK', size_hint_y=None, height=40)
        popup = Popup(title='Test Users', content=content, size_hint=(0.8, 0.6))
        btn.bind(on_press=popup.dismiss)
        content.add_widget(btn)
        popup.open()

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message, font_size='16sp'))

        btn = Button(text='OK', size_hint_y=None, height=40)
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))
        btn.bind(on_press=popup.dismiss)
        content.add_widget(btn)
        popup.open()

class ChatBubble(BoxLayout):
    def __init__(self, text, is_me=False, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.size_hint_y = None
        self.height = 60
        self.padding = [10, 5, 10, 5]

        if is_me:
            self.add_widget(Label(size_hint_x=0.3))

            bubble = BoxLayout(orientation='vertical')
            bubble.add_widget(Label(text='You', size_hint_y=None, height=20, color=(0.5, 0.5, 0.5, 1), font_size='12sp'))
            bubble.add_widget(Label(text=text, color=(0, 0, 0, 1), font_size='14sp', halign='right'))
            self.add_widget(bubble)

            color_box = BoxLayout(size_hint_x=0.1)
            color_box.canvas.before.clear()
            with color_box.canvas.before:
                from kivy.graphics import Color, RoundedRectangle
                Color(0.07, 0.55, 0.49, 1)
                RoundedRectangle(pos=color_box.pos, size=color_box.size, radius=[20])
            self.add_widget(color_box)
        else:
            color_box = BoxLayout(size_hint_x=0.1)
            color_box.canvas.before.clear()
            with color_box.canvas.before:
                from kivy.graphics import Color, RoundedRectangle
                Color(0.2, 0.2, 0.2, 1)
                RoundedRectangle(pos=color_box.pos, size=color_box.size, radius=[20])
            self.add_widget(color_box)

            bubble = BoxLayout(orientation='vertical')
            bubble.add_widget(Label(text='Them', size_hint_y=None, height=20, color=(0.5, 0.5, 0.5, 1), font_size='12sp'))
            bubble.add_widget(Label(text=text, color=(1, 1, 1, 1), font_size='14sp'))
            self.add_widget(bubble)

            self.add_widget(Label(size_hint_x=0.3))

class ChatsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.current_chat_user = None

        main_layout = BoxLayout(orientation='horizontal')

        # Left panel - Contacts
        left_panel = BoxLayout(orientation='vertical', size_hint=(0.3, 1))

        header = BoxLayout(size_hint_y=None, height=60)
        user_label = Label(text='Loading...', font_size='18sp', bold=True)
        header.add_widget(user_label)

        logout_btn = Button(
            text='Logout',
            size_hint_x=None,
            width=80,
            background_color=(0.9, 0.2, 0.2, 1)
        )
        logout_btn.bind(on_press=self.logout)
        header.add_widget(logout_btn)

        left_panel.add_widget(header)

        self.contacts_scroll = ScrollView()
        self.contacts_layout = GridLayout(cols=1, spacing=5, size_hint_y=None)
        self.contacts_layout.bind(minimum_height=self.contacts_layout.setter('height'))
        self.contacts_scroll.add_widget(self.contacts_layout)
        left_panel.add_widget(self.contacts_scroll)

        # Right panel - Chat
        right_panel = BoxLayout(orientation='vertical', size_hint=(0.7, 1))

        self.chat_header = Label(
            text='Select a contact to chat',
            size_hint_y=None,
            height=60,
            font_size='20sp',
            bold=True
        )
        right_panel.add_widget(self.chat_header)

        self.chat_scroll = ScrollView()
        self.chat_layout = GridLayout(cols=1, spacing=5, size_hint_y=None)
        self.chat_layout.bind(minimum_height=self.chat_layout.setter('height'))
        self.chat_scroll.add_widget(self.chat_layout)
        right_panel.add_widget(self.chat_scroll)

        input_panel = BoxLayout(size_hint_y=None, height=60, spacing=10, padding=10)
        self.message_input = TextInput(
            hint_text='Type message...',
            multiline=False,
            background_color=(1, 1, 1, 0.1)
        )
        input_panel.add_widget(self.message_input)

        send_btn = Button(
            text='Send',
            size_hint_x=None,
            width=80,
            background_color=(0.07, 0.55, 0.49, 1)
        )
        send_btn.bind(on_press=self.send_message)
        input_panel.add_widget(send_btn)

        right_panel.add_widget(input_panel)

        main_layout.add_widget(left_panel)
        main_layout.add_widget(right_panel)

        self.add_widget(main_layout)

        self.user_label = user_label
        self.refresh_timer = None

    def on_pre_enter(self):
        app = App.get_running_app()
        self.user_label.text = f"👤 {app.current_user['username']}"
        self.load_contacts()

        if self.refresh_timer is None:
            self.refresh_timer = Clock.schedule_interval(lambda dt: self.refresh_chat(), 2)

    def load_contacts(self):
        def load():
            app = App.get_running_app()
            result = app.backend.get_users()

            if result['success']:
                Clock.schedule_once(lambda dt: self.display_contacts(result['data']), 0)

        threading.Thread(target=load).start()

    def display_contacts(self, users):
        self.contacts_layout.clear_widgets()

        for user in users:
            btn = Button(
                text=f"{user['username']} {'🟢' if user['is_online'] else '⚫'}",
                size_hint_y=None,
                height=60,
                background_color=(0.2, 0.2, 0.2, 1) if user['is_online'] else (0.1, 0.1, 0.1, 1)
            )
            btn.user_data = user
            btn.bind(on_press=self.select_contact)
            self.contacts_layout.add_widget(btn)

    def select_contact(self, instance):
        self.current_chat_user = instance.user_data
        self.chat_header.text = f"💬 Chat with {self.current_chat_user['username']}"
        self.load_chat_messages()

    def load_chat_messages(self):
        if not self.current_chat_user:
            return

        def load():
            app = App.get_running_app()
            result = app.backend.get_chat_messages(self.current_chat_user['id'])

            if result['success']:
                Clock.schedule_once(lambda dt: self.display_messages(result['data']), 0)

        threading.Thread(target=load).start()

    def display_messages(self, messages):
        self.chat_layout.clear_widgets()

        if not messages:
            self.chat_layout.add_widget(Label(
                text=f'Start chatting with {self.current_chat_user["username"]}!',
                size_hint_y=None,
                height=40,
                color=(0.5, 0.5, 0.5, 1)
            ))
            return

        for msg in messages:
            bubble = ChatBubble(
                text=msg['content'][:100] + ('...' if len(msg['content']) > 100 else ''),
                is_me=msg['is_me']
            )
            self.chat_layout.add_widget(bubble)

        Clock.schedule_once(lambda dt: self.chat_scroll.scroll_to(self.chat_layout.children[0] if self.chat_layout.children else None), 0.1)

    def send_message(self, instance):
        if not self.current_chat_user or not self.message_input.text.strip():
            return

        message = self.message_input.text.strip()
        self.message_input.text = ''

        def send():
            app = App.get_running_app()
            result = app.backend.send_message(self.current_chat_user['id'], message)

            if result['success']:
                Clock.schedule_once(lambda dt: self.load_chat_messages(), 0.1)
            else:
                Clock.schedule_once(lambda dt: self.show_error("Send failed"), 0)

        threading.Thread(target=send).start()

    def refresh_chat(self):
        if self.current_chat_user:
            self.load_chat_messages()

    def show_error(self, message):
        popup = Popup(
            title='Error',
            content=Label(text=message),
            size_hint=(0.6, 0.4)
        )
        popup.open()

    def logout(self, instance):
        if self.refresh_timer:
            self.refresh_timer.cancel()
            self.refresh_timer = None

        app = App.get_running_app()
        app.current_user = None
        app.sm.current = 'login'

class EEncryptApp(App):
    def build(self):
        self.title = "E-Encrypt Desktop"
        Window.size = (900, 600)
        Window.clearcolor = (0.05, 0.05, 0.05, 1)

        self.backend = BackendClient()
        self.current_user = None
        self.sm = ScreenManager()

        self.sm.add_widget(LoginScreen(name='login'))
        self.sm.add_widget(ChatsScreen(name='chats'))

        return self.sm

if __name__ == "__main__":
    print("🚀 Starting E-Encrypt Desktop App...")
    print("Make sure backend is running on http://localhost:8000")
    EEncryptApp().run()
""",

        "start_all.py": """#!/usr/bin/env python3
\"\"\"
🚀 E-Encrypt Startup Script
Starts all applications at once
\"\"\"

import subprocess
import sys
import os
import time
import webbrowser
from datetime import datetime

def start_backend():
    print("🚀 Starting Backend API...")
    backend_proc = subprocess.Popen(
        [sys.executable, "backend_api.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    time.sleep(3)  # Give backend time to start

    # Check if backend is running
    try:
        import requests
        response = requests.get("http://localhost:8000/api/health", timeout=2)
        if response.status_code == 200:
            print("✅ Backend is running at http://localhost:8000")
            return backend_proc
        else:
            print("⚠️  Backend started but health check failed")
            return backend_proc
    except:
        print("⚠️  Backend may not be fully started")
        return backend_proc

def start_web_app():
    print("🌐 Starting Web Application...")
    web_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "main_web_backend.py", "--server.port", "8501", "--server.headless", "true"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    time.sleep(2)

    # Open browser after delay
    def open_browser():
        time.sleep(3)
        print("🌐 Opening web browser...")
        webbrowser.open("http://localhost:8501")

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    return web_proc

def start_desktop_app():
    print("💻 Starting Desktop Application...")
    desktop_proc = subprocess.Popen(
        [sys.executable, "main_desktop_backend.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    time.sleep(1)
    return desktop_proc

def main():
    print("=" * 60)
    print("🔐 E-ENCRYPT - ALL APPLICATIONS")
    print("=" * 60)
    print()
    print("Starting all applications...")
    print("You can access:")
    print("  • Backend API:    http://localhost:8000")
    print("  • Web App:        http://localhost:8501")
    print("  • Desktop App:    Will open automatically")
    print()
    print("Test users: alice, bob, charlie, david, emma")
    print("Password for all: password123")
    print()
    print("Press Ctrl+C to stop all applications")
    print()

    processes = []

    try:
        # Start backend
        backend_proc = start_backend()
        processes.append(("Backend API", backend_proc))

        # Start web app
        web_proc = start_web_app()
        processes.append(("Web App", web_proc))

        # Start desktop app
        desktop_proc = start_desktop_app()
        processes.append(("Desktop App", desktop_proc))

        print()
        print("=" * 60)
        print("✅ ALL APPLICATIONS STARTED!")
        print("=" * 60)
        print()
        print("Applications running:")
        print("  1. Backend API - http://localhost:8000")
        print("  2. Web Interface - http://localhost:8501")
        print("  3. Desktop App - Running in window")
        print()
        print("To stop all applications, press Ctrl+C")
        print()

        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping all applications...")

    except KeyboardInterrupt:
        print("\n🛑 Installation interrupted")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        # Kill all processes
        for name, proc in processes:
            if proc and proc.poll() is None:
                print(f"  Stopping {name}...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except:
                    proc.kill()

        print()
        print("✅ All applications stopped")
        print("=" * 60)

if __name__ == "__main__":
    main()
""",

        "requirements.txt": """# Backend
fastapi==0.104.0
uvicorn[standard]==0.24.0
sqlalchemy==2.0.23
pycryptodome==3.19.0
PyJWT==2.8.0
python-multipart==0.0.6
requests==2.31.0

# Web App
streamlit==1.28.0
pillow==10.0.0

# Desktop App
kivy==2.3.0
websocket-client==1.6.4
""",

        "README.md": """# 🔐 E-Encrypt - Secure Messenger System

A complete end-to-end encrypted messaging system with multiple interfaces.

## 📋 Features

- ✅ **Backend API** - FastAPI-based REST API with WebSocket support
- ✅ **Web Interface** - Streamlit-based web application
- ✅ **Desktop App** - Kivy-based desktop application
- ✅ **Real-time messaging** - Instant message delivery
- ✅ **User status** - Online/offline indicators
- ✅ **Message encryption** - AES encryption support
- ✅ **Multiple users** - Pre-configured test users
- ✅ **Database** - SQLite with SQLAlchemy ORM
- ✅ **JWT Authentication** - Secure token-based auth

## 🚀 Quick Start

### Option 1: Complete Installation & Start
```bash
# Install everything
python install_all.py

# Start all applications
python start_all.py