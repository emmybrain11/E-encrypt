from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import hashlib
import jwt  # This is PyJWT
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
                "content": last_message.content[:50] + "..." if last_message and len(
                    last_message.content) > 50 else last_message.content if last_message else "No messages",
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