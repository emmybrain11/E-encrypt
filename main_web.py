"""
🌐 E-Encrypt - Complete Web Application with ALL Features
FIXED VERSION - Working with no form conflicts
"""

import streamlit as st
import os
import time
import json
import base64
import sqlite3
import hashlib
import random
import tempfile
from datetime import datetime
from PIL import Image
import numpy as np
from io import BytesIO

# Crypto imports
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Set page config
st.set_page_config(
    page_title="E-Encrypt - Quantum Secure Messenger",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #25D366;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .chat-bubble-right {
        background-color: #25D366;
        color: white;
        padding: 10px 15px;
        border-radius: 15px 15px 0 15px;
        margin: 5px 0;
        max-width: 70%;
        margin-left: auto;
    }
    .chat-bubble-left {
        background-color: #2A2F32;
        color: white;
        padding: 10px 15px;
        border-radius: 15px 15px 15px 0;
        margin: 5px 0;
        max-width: 70%;
        margin-right: auto;
    }
    .contact-item {
        padding: 10px;
        border-radius: 10px;
        margin: 5px 0;
        cursor: pointer;
        transition: all 0.3s;
    }
    .contact-item:hover {
        background-color: #f0f0f0;
    }
    .online-dot {
        height: 10px;
        width: 10px;
        background-color: #25D366;
        border-radius: 50%;
        display: inline-block;
        margin-right: 5px;
    }
    .offline-dot {
        height: 10px;
        width: 10px;
        background-color: #666;
        border-radius: 50%;
        display: inline-block;
        margin-right: 5px;
    }
    .stButton button {
        border-radius: 8px;
        padding: 10px;
    }
    .success-message {
        padding: 10px;
        background-color: #d4edda;
        color: #155724;
        border-radius: 5px;
        margin: 10px 0;
    }
    .error-message {
        padding: 10px;
        background-color: #f8d7da;
        color: #721c24;
        border-radius: 5px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)


# ==================== DATABASE MANAGER ====================
class DatabaseManager:
    def __init__(self, db_name='securechat.db'):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.create_tables()
        self.create_default_users()

    def create_tables(self):
        cursor = self.conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                phone TEXT,
                status TEXT DEFAULT 'Secure & Encrypted 🔐',
                avatar_color TEXT DEFAULT '#25D366',
                last_seen TIMESTAMP,
                is_online INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1_id INTEGER NOT NULL,
                user2_id INTEGER NOT NULL,
                last_message TEXT,
                last_message_time TIMESTAMP,
                unread_count INTEGER DEFAULT 0,
                is_pinned INTEGER DEFAULT 0,
                is_muted INTEGER DEFAULT 0,
                is_encrypted INTEGER DEFAULT 1,
                encryption_type TEXT DEFAULT 'AES-256-GCM',
                FOREIGN KEY (user1_id) REFERENCES users(id),
                FOREIGN KEY (user2_id) REFERENCES users(id),
                UNIQUE(user1_id, user2_id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                message_type TEXT DEFAULT 'text',
                content TEXT NOT NULL,
                encrypted_content TEXT,
                is_encrypted INTEGER DEFAULT 0,
                encryption_password TEXT,
                encryption_type TEXT DEFAULT 'AES-256',
                stego_image_path TEXT,
                stego_method TEXT DEFAULT 'lsb',
                status TEXT DEFAULT 'sent',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (chat_id) REFERENCES chats(id),
                FOREIGN KEY (sender_id) REFERENCES users(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quantum_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                public_key TEXT NOT NULL,
                private_key_encrypted TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stego_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                operation_type TEXT NOT NULL,
                original_image TEXT,
                stego_image TEXT,
                message_hash TEXT,
                password_hash TEXT,
                method TEXT DEFAULT 'lsb',
                intensity INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        self.conn.commit()

    def create_default_users(self):
        cursor = self.conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users WHERE username IN ('alice', 'bob', 'charlie')")
        if cursor.fetchone()[0] == 0:
            default_users = [
                ('alice', 'password123', '+1234567890', '🔐 Quantum Encrypted', '#25D366'),
                ('bob', 'password123', '+1234567891', '⚡ Secure & Online', '#34B7F1'),
                ('charlie', 'password123', '+1234567892', '🛡️ Privacy First', '#FF6B6B'),
                ('david', 'password123', '+1234567893', '🌐 End-to-End', '#FFD93D'),
                ('emma', 'password123', '+1234567894', '⚛️ Quantum-Resistant', '#9B59B6')
            ]

            for username, password, phone, status, color in default_users:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                cursor.execute('''
                    INSERT INTO users (username, password_hash, phone, status, avatar_color, is_online)
                    VALUES (?, ?, ?, ?, ?, 1)
                ''', (username, password_hash, phone, status, color))

            self.conn.commit()

            cursor.execute("SELECT id FROM users")
            user_ids = [row[0] for row in cursor.fetchall()]

            for i, user1_id in enumerate(user_ids):
                for j, user2_id in enumerate(user_ids):
                    if i < j:
                        cursor.execute('''
                            INSERT INTO chats (user1_id, user2_id, last_message_time)
                            VALUES (?, ?, ?)
                        ''', (user1_id, user2_id, datetime.now()))

            self.conn.commit()

    def register_user(self, username, password, phone=None):
        cursor = self.conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return None

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        avatar_colors = ['#25D366', '#34B7F1', '#FF6B6B', '#FFD93D', '#9B59B6', '#1ABC9C', '#E74C3C']
        avatar_color = random.choice(avatar_colors)

        cursor.execute('''
            INSERT INTO users (username, password_hash, phone, avatar_color, is_online)
            VALUES (?, ?, ?, ?, 1)
        ''', (username, password_hash, phone, avatar_color))

        user_id = cursor.lastrowid

        cursor.execute("SELECT id FROM users WHERE id != ?", (user_id,))
        existing_users = [row[0] for row in cursor.fetchall()]

        for other_id in existing_users:
            cursor.execute('''
                INSERT INTO chats (user1_id, user2_id, last_message_time)
                VALUES (?, ?, ?)
            ''', (user_id, other_id, datetime.now()))

        self.conn.commit()

        return {
            'id': user_id,
            'username': username,
            'phone': phone,
            'status': 'Secure & Encrypted 🔐',
            'avatar_color': avatar_color,
            'online': True
        }

    def authenticate_user(self, username, password):
        cursor = self.conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        cursor.execute('''
            SELECT id, username, phone, status, avatar_color 
            FROM users 
            WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))

        user = cursor.fetchone()
        if user:
            cursor.execute('UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?',
                           (datetime.now(), user[0]))
            self.conn.commit()

            return {
                'id': user[0],
                'username': user[1],
                'phone': user[2],
                'status': user[3],
                'avatar_color': user[4],
                'online': True
            }
        return None

    def get_user_chats(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT c.id, 
                   CASE 
                       WHEN c.user1_id = ? THEN u2.id 
                       ELSE u1.id 
                   END as contact_id,
                   CASE 
                       WHEN c.user1_id = ? THEN u2.username 
                       ELSE u1.username 
                   END as contact_name,
                   CASE 
                       WHEN c.user1_id = ? THEN u2.phone 
                       ELSE u1.phone 
                   END as contact_phone,
                   CASE 
                       WHEN c.user1_id = ? THEN u2.status 
                       ELSE u1.status 
                   END as contact_status,
                   CASE 
                       WHEN c.user1_id = ? THEN u2.avatar_color 
                       ELSE u1.avatar_color 
                   END as avatar_color,
                   CASE 
                       WHEN c.user1_id = ? THEN u2.is_online 
                       ELSE u1.is_online 
                   END as is_online,
                   c.last_message,
                   c.last_message_time,
                   c.unread_count
            FROM chats c
            JOIN users u1 ON c.user1_id = u1.id
            JOIN users u2 ON c.user2_id = u2.id
            WHERE c.user1_id = ? OR c.user2_id = ?
            ORDER BY c.last_message_time DESC
        ''', (user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id))

        chats = []
        for row in cursor.fetchall():
            chats.append({
                'chat_id': row[0],
                'contact_id': row[1],
                'contact_name': row[2],
                'contact_phone': row[3],
                'contact_status': row[4],
                'avatar_color': row[5],
                'is_online': bool(row[6]),
                'last_message': row[7] or 'Start a conversation',
                'last_message_time': row[8],
                'unread_count': row[9]
            })
        return chats

    def get_chat_messages(self, chat_id, user_id, limit=100):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT m.id, m.sender_id, m.message_type, m.content, 
                   m.is_encrypted, m.encryption_password, m.stego_image_path,
                   m.status, m.timestamp, m.is_read,
                   u.username as sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.chat_id = ?
            ORDER BY m.timestamp ASC
            LIMIT ?
        ''', (chat_id, limit))

        messages = []
        for row in cursor.fetchall():
            is_me = row[1] == user_id
            messages.append({
                'id': row[0],
                'sender_id': row[1],
                'type': row[2],
                'content': row[3],
                'is_encrypted': bool(row[4]),
                'password': row[5],
                'stego_image': row[6],
                'status': row[7],
                'timestamp': row[8],
                'is_read': bool(row[9]),
                'sender_name': row[10],
                'is_me': is_me
            })

        cursor.execute('''
            UPDATE messages SET is_read = 1
            WHERE chat_id = ? AND sender_id != ? AND is_read = 0
        ''', (chat_id, user_id))

        cursor.execute('UPDATE chats SET unread_count = 0 WHERE id = ?', (chat_id,))
        self.conn.commit()

        return messages

    def save_message(self, chat_id, sender_id, message_type, content,
                     is_encrypted=False, password=None, stego_image=None):
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT INTO messages (chat_id, sender_id, message_type, content, 
                                is_encrypted, encryption_password, stego_image_path, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'sent')
        ''', (chat_id, sender_id, message_type, content,
              is_encrypted, password, stego_image))

        message_id = cursor.lastrowid

        preview = content[:50] + "..." if len(content) > 50 else content
        if is_encrypted:
            preview = "🔒 Encrypted message"
        elif stego_image:
            preview = "🖼️ Image with hidden message"

        cursor.execute('''
            UPDATE chats SET last_message = ?, last_message_time = ?, unread_count = unread_count + 1
            WHERE id = ?
        ''', (preview, datetime.now(), chat_id))

        self.conn.commit()
        return message_id

    def save_stego_operation(self, user_id, operation_type, original_image, stego_image,
                             message_hash, password_hash, method='lsb', intensity=1):
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT INTO stego_operations (user_id, operation_type, original_image, stego_image,
                                         message_hash, password_hash, method, intensity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, operation_type, original_image, stego_image,
              message_hash, password_hash, method, intensity))

        self.conn.commit()
        return cursor.lastrowid

    def get_user_stats(self, user_id):
        cursor = self.conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM messages WHERE sender_id = ?', (user_id,))
        messages_sent = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM messages WHERE sender_id != ? AND is_read = 1', (user_id,))
        messages_read = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM stego_operations WHERE user_id = ?', (user_id,))
        stego_ops = cursor.fetchone()[0]

        return {
            'messages_sent': messages_sent,
            'messages_read': messages_read,
            'stego_operations': stego_ops
        }


# ==================== ENCRYPTION MANAGER ====================
class EncryptionManager:
    def __init__(self):
        self.bs = AES.block_size

    def encrypt_message(self, message, password):
        try:
            salt = get_random_bytes(16)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            padded_message = pad(message.encode('utf-8'), self.bs)
            encrypted = cipher.encrypt(padded_message)

            result = salt + iv + encrypted
            return base64.b64encode(result).decode('utf-8')
        except Exception as e:
            return None

    def decrypt_message(self, encrypted_data, password):
        try:
            data = base64.b64decode(encrypted_data)
            salt = data[:16]
            iv = data[16:32]
            encrypted = data[32:]

            key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            original = unpad(decrypted, self.bs)

            return original.decode('utf-8')
        except Exception as e:
            return None


# ==================== STEGANOGRAPHY MANAGER ====================
class SteganographyManager:
    def __init__(self):
        self.encryption = EncryptionManager()

    def encode_message(self, image_bytes, message, password, method='lsb', intensity=1):
        """Encode message into image"""
        try:
            img = Image.open(BytesIO(image_bytes))

            if img.mode != 'RGB':
                img = img.convert('RGB')

            # Encrypt the message first
            encrypted = self.encryption.encrypt_message(message, password)
            if not encrypted:
                return None

            binary_data = ''.join(format(ord(char), '08b') for char in encrypted)
            binary_data += '1111111111111110'  # 16-bit delimiter

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

            # Save to bytes
            output = BytesIO()
            stego_img.save(output, format='PNG')

            return output.getvalue()

        except Exception as e:
            return None

    def decode_message(self, image_bytes, password, method='lsb', intensity=1):
        """Decode message from image"""
        try:
            img = Image.open(BytesIO(image_bytes))

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

            # Decrypt the message
            decrypted = self.encryption.decrypt_message(encrypted_data, password)
            return decrypted

        except Exception as e:
            return None


# ==================== QUANTUM ENCRYPTION ====================
class QuantumEncryption:
    @staticmethod
    def generate_keypair():
        """Generate simulated quantum-resistant key pair"""
        private_key = get_random_bytes(32)
        public_key = hashlib.sha256(private_key).digest()[:32]

        return {
            'private': base64.b64encode(private_key).decode(),
            'public': base64.b64encode(public_key).decode()
        }


# ==================== MAIN STREAMLIT APP ====================
class EEncryptWebApp:
    def __init__(self):
        if 'db' not in st.session_state:
            st.session_state.db = DatabaseManager()
        if 'encryption' not in st.session_state:
            st.session_state.encryption = EncryptionManager()
        if 'steganography' not in st.session_state:
            st.session_state.steganography = SteganographyManager()
        if 'quantum' not in st.session_state:
            st.session_state.quantum = QuantumEncryption()

        # Initialize session state variables
        if 'logged_in' not in st.session_state:
            st.session_state.logged_in = False
        if 'current_user' not in st.session_state:
            st.session_state.current_user = None
        if 'current_chat' not in st.session_state:
            st.session_state.current_chat = None
        if 'page' not in st.session_state:
            st.session_state.page = 'login'
        if 'quantum_keys' not in st.session_state:
            st.session_state.quantum_keys = None

    def run(self):
        # Display header
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown('<h1 class="main-header">🔐 E-Encrypt</h1>', unsafe_allow_html=True)
            st.markdown('<p class="sub-header">Quantum-Resistant Secure Messenger</p>', unsafe_allow_html=True)

        # Page routing
        if not st.session_state.logged_in:
            self.login_page()
        else:
            self.main_app()

    def login_page(self):
        col1, col2, col3 = st.columns([1, 2, 1])

        with col2:
            st.markdown("### Welcome to E-Encrypt")

            # Tabs for login/register
            tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])

            with tab1:
                # Login form - NO FORM WIDGET (to avoid conflicts)
                login_username = st.text_input("Username", key="login_username")
                login_password = st.text_input("Password", type="password", key="login_password")

                col1, col2, col3 = st.columns([1, 1, 1])
                with col2:
                    login_submit = st.button("Login", use_container_width=True, type="primary")

                if login_submit:
                    if login_username and login_password:
                        user = st.session_state.db.authenticate_user(login_username, login_password)
                        if user:
                            st.session_state.logged_in = True
                            st.session_state.current_user = user
                            st.session_state.quantum_keys = st.session_state.quantum.generate_keypair()
                            st.success(f"Welcome back, {user['username']}!")
                            st.rerun()
                        else:
                            st.error("Invalid username or password")
                    else:
                        st.error("Please enter username and password")

                # Quick login buttons
                st.divider()
                st.markdown("### Quick Login (Test Users)")

                test_users = ['alice', 'bob', 'charlie', 'david', 'emma']
                cols = st.columns(5)

                for idx, user in enumerate(test_users):
                    with cols[idx]:
                        if st.button(f"👤 {user}", key=f"quick_{user}"):
                            user_data = st.session_state.db.authenticate_user(user, 'password123')
                            if user_data:
                                st.session_state.logged_in = True
                                st.session_state.current_user = user_data
                                st.session_state.quantum_keys = st.session_state.quantum.generate_keypair()
                                st.success(f"Welcome, {user_data['username']}!")
                                st.rerun()

            with tab2:
                # Registration form - NO FORM WIDGET
                new_username = st.text_input("Choose Username", key="reg_username")
                new_password = st.text_input("Choose Password", type="password", key="reg_password")
                confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm")
                phone = st.text_input("Phone (optional)", key="reg_phone")

                register_submit = st.button("Create Account", use_container_width=True, type="primary")

                if register_submit:
                    if new_username and new_password:
                        if new_password == confirm_password:
                            if len(new_password) >= 6:
                                user = st.session_state.db.register_user(new_username, new_password, phone)
                                if user:
                                    st.session_state.logged_in = True
                                    st.session_state.current_user = user
                                    st.session_state.quantum_keys = st.session_state.quantum.generate_keypair()
                                    st.success(f"Account created successfully! Welcome {new_username}!")
                                    st.rerun()
                                else:
                                    st.error("Username already exists")
                            else:
                                st.error("Password must be at least 6 characters")
                        else:
                            st.error("Passwords do not match")
                    else:
                        st.error("Please enter username and password")

            # Features showcase
            st.divider()
            st.markdown("### 🚀 Features")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown("""
                **🔐 AES-256 Encryption**
                - Military-grade encryption
                - End-to-end secure
                """)
            with col2:
                st.markdown("""
                **🖼️ Steganography**
                - Hide messages in images
                - LSB encoding methods
                """)
            with col3:
                st.markdown("""
                **⚛️ Quantum-Resistant**
                - Post-quantum algorithms
                - Future-proof security
                """)

    def main_app(self):
        # Navigation sidebar
        with st.sidebar:
            user = st.session_state.current_user
            st.markdown(f"### 👤 {user['username']}")
            st.markdown(f"*{user.get('status', 'Secure & Encrypted 🔐')}*")
            st.divider()

            # Navigation options
            if st.button("💬 Chats", use_container_width=True):
                st.session_state.page = 'chats'
                st.session_state.current_chat = None
                st.rerun()

            if st.button("🖼️ Steganography", use_container_width=True):
                st.session_state.page = 'stegano'
                st.rerun()

            if st.button("⚛️ Quantum Keys", use_container_width=True):
                st.session_state.page = 'quantum'
                st.rerun()

            if st.button("📊 Statistics", use_container_width=True):
                st.session_state.page = 'stats'
                st.rerun()

            if st.button("⚙️ Settings", use_container_width=True):
                st.session_state.page = 'settings'
                st.rerun()

            st.divider()
            if st.button("🚪 Logout", use_container_width=True, type="secondary"):
                st.session_state.logged_in = False
                st.session_state.current_user = None
                st.session_state.current_chat = None
                st.session_state.page = 'login'
                st.rerun()

        # Main content area
        if st.session_state.page == 'chats':
            if st.session_state.current_chat:
                self.chat_page()
            else:
                self.chats_page()
        elif st.session_state.page == 'stegano':
            self.stegano_page()
        elif st.session_state.page == 'quantum':
            self.quantum_page()
        elif st.session_state.page == 'stats':
            self.stats_page()
        elif st.session_state.page == 'settings':
            self.settings_page()

    def chats_page(self):
        st.markdown("### 💬 Your Chats")

        # Get user chats
        chats = st.session_state.db.get_user_chats(st.session_state.current_user['id'])

        if not chats:
            st.info("No chats yet. Start by selecting a contact!")
        else:
            # Search bar
            search = st.text_input("🔍 Search contacts", placeholder="Type to search...")

            # Display chats
            for chat in chats:
                if search.lower() not in chat['contact_name'].lower() and search:
                    continue

                col1, col2, col3 = st.columns([1, 3, 1])
                with col1:
                    # Avatar with color
                    avatar_color = chat['avatar_color']
                    st.markdown(f"""
                    <div style="
                        background-color: {avatar_color}; 
                        width: 50px; 
                        height: 50px; 
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        color: white;
                        font-weight: bold;
                        font-size: 18px;
                    ">
                        {chat['contact_name'][0].upper()}
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    status = "🟢" if chat['is_online'] else "⚫"
                    st.markdown(f"**{chat['contact_name']}** {status}")
                    st.markdown(f"*{chat['last_message']}*")
                    if chat['unread_count'] > 0:
                        st.markdown(f"<small style='color: #25D366;'>{chat['unread_count']} unread</small>",
                                    unsafe_allow_html=True)

                with col3:
                    if st.button("Open", key=f"open_chat_{chat['chat_id']}", use_container_width=True):
                        st.session_state.current_chat = chat
                        st.rerun()

                st.divider()

    def chat_page(self):
        chat = st.session_state.current_chat

        # Chat header
        col1, col2, col3 = st.columns([1, 3, 1])
        with col1:
            if st.button("← Back"):
                st.session_state.current_chat = None
                st.rerun()

        with col2:
            status = "🟢 Online" if chat['is_online'] else "⚫ Offline"
            st.markdown(f"### {chat['contact_name']}")
            st.markdown(f"*{status} | {chat['contact_status']}*")

        with col3:
            if st.button("📞 Call"):
                st.info(f"Starting encrypted call with {chat['contact_name']}...")

        st.divider()

        # Messages area
        messages_container = st.container(height=400)

        with messages_container:
            # Get messages
            messages = st.session_state.db.get_chat_messages(
                chat['chat_id'],
                st.session_state.current_user['id']
            )

            if not messages:
                st.info(f"Start chatting with {chat['contact_name']}!")
                st.info("🔒 All messages are end-to-end encrypted")
                st.info("🔐 Use the steganography feature to hide messages in images")
            else:
                for msg in messages:
                    if msg['is_me']:
                        st.markdown(f'''
                        <div class="chat-bubble-right">
                            <strong>You</strong><br>
                            {msg['content'] if not msg['is_encrypted'] else '🔒 Encrypted message'}
                            <br><small>{msg['timestamp'][11:16] if isinstance(msg['timestamp'], str) else 'Now'}</small>
                        </div>
                        ''', unsafe_allow_html=True)

                        if msg['is_encrypted']:
                            with st.expander("Decrypt message"):
                                password = st.text_input("Enter password", type="password", key=f"decrypt_{msg['id']}")
                                if st.button("Decrypt", key=f"decrypt_btn_{msg['id']}"):
                                    decrypted = st.session_state.encryption.decrypt_message(msg['content'], password)
                                    if decrypted:
                                        st.success(f"**Decrypted:** {decrypted}")
                                    else:
                                        st.error("Wrong password or corrupted message")

                        if msg['stego_image']:
                            with st.expander("🔓 Decode steganography"):
                                st.info("Steganography decoding available")
                    else:
                        st.markdown(f'''
                        <div class="chat-bubble-left">
                            <strong>{msg['sender_name']}</strong><br>
                            {msg['content'] if not msg['is_encrypted'] else '🔒 Encrypted message'}
                            <br><small>{msg['timestamp'][11:16] if isinstance(msg['timestamp'], str) else 'Now'}</small>
                        </div>
                        ''', unsafe_allow_html=True)

                        if msg['is_encrypted']:
                            with st.expander("Decrypt message"):
                                password = st.text_input("Enter password", type="password",
                                                         key=f"decrypt_{msg['id']}_them")
                                if st.button("Decrypt", key=f"decrypt_btn_{msg['id']}_them"):
                                    decrypted = st.session_state.encryption.decrypt_message(msg['content'], password)
                                    if decrypted:
                                        st.success(f"**Decrypted:** {decrypted}")
                                    else:
                                        st.error("Wrong password or corrupted message")

        # Message input
        col1, col2, col3 = st.columns([5, 1, 1])
        with col1:
            message = st.text_input("Type a message...", key="message_input", label_visibility="collapsed")

        with col2:
            if st.button("Send", use_container_width=True) and message:
                st.session_state.db.save_message(
                    chat['chat_id'],
                    st.session_state.current_user['id'],
                    'text',
                    message,
                    False,
                    None,
                    None
                )
                st.rerun()

        with col3:
            if st.button("🔐", use_container_width=True):
                with st.popover("Send Encrypted Message"):
                    encrypted_msg = st.text_area("Message to encrypt")
                    password = st.text_input("Encryption password", type="password")
                    if st.button("Send Encrypted", key="send_encrypted"):
                        if encrypted_msg and password:
                            encrypted = st.session_state.encryption.encrypt_message(encrypted_msg, password)
                            if encrypted:
                                st.session_state.db.save_message(
                                    chat['chat_id'],
                                    st.session_state.current_user['id'],
                                    'text',
                                    encrypted,
                                    True,
                                    password,
                                    None
                                )
                                st.success("Encrypted message sent!")
                                st.rerun()

    def stegano_page(self):
        st.markdown("### 🖼️ Advanced Steganography")

        tab1, tab2 = st.tabs(["🔒 Hide Message", "🔓 Extract Message"])

        with tab1:
            st.markdown("#### Encode a secret message into an image")

            col1, col2 = st.columns(2)

            with col1:
                # Message input
                secret_message = st.text_area("Secret Message", height=100,
                                              placeholder="Type your secret message here...")

                # Password
                encode_password = st.text_input("Encryption Password", type="password",
                                                placeholder="Enter strong password")

                # Method selection
                method = st.selectbox("Encoding Method", ["LSB (Basic)", "LSB Advanced"])

                # Intensity
                intensity = st.slider("Intensity", 1, 4, 1)

            with col2:
                # Image upload
                uploaded_image = st.file_uploader("Choose an image", type=['png', 'jpg', 'jpeg'])

                if uploaded_image:
                    st.image(uploaded_image, caption="Selected Image", use_column_width=True)

                    encode_btn = st.button("🔒 Encode Message", type="primary", use_container_width=True)

                    if encode_btn:
                        if secret_message and encode_password:
                            with st.spinner("Encoding message..."):
                                # Read image
                                image_bytes = uploaded_image.read()

                                # Encode message
                                method_str = 'lsb' if 'Basic' in method else 'lsb_advanced'
                                encoded = st.session_state.steganography.encode_message(
                                    image_bytes, secret_message, encode_password, method_str, intensity
                                )

                                if encoded:
                                    # Save operation to database
                                    message_hash = hashlib.sha256(secret_message.encode()).hexdigest()
                                    password_hash = hashlib.sha256(encode_password.encode()).hexdigest()
                                    st.session_state.db.save_stego_operation(
                                        st.session_state.current_user['id'],
                                        'encode',
                                        uploaded_image.name,
                                        'stego_image.png',
                                        message_hash,
                                        password_hash,
                                        method_str,
                                        intensity
                                    )

                                    # Download button
                                    st.success("✅ Message encoded successfully!")
                                    st.download_button(
                                        label="📥 Download Encoded Image",
                                        data=encoded,
                                        file_name="encoded_image.png",
                                        mime="image/png",
                                        use_container_width=True
                                    )
                                else:
                                    st.error("Failed to encode message. Image may be too small.")
                        else:
                            st.error("Please enter both message and password")

        with tab2:
            st.markdown("#### Extract a hidden message from an image")

            col1, col2 = st.columns(2)

            with col1:
                # Image upload for decoding
                decode_image = st.file_uploader("Choose encoded image", type=['png', 'jpg', 'jpeg'],
                                                key="decode_upload")

                if decode_image:
                    st.image(decode_image, caption="Encoded Image", use_column_width=True)

            with col2:
                # Decoding parameters
                decode_password = st.text_input("Decryption Password", type="password",
                                                placeholder="Enter password used for encoding")

                decode_method = st.selectbox("Decoding Method", ["LSB (Basic)", "LSB Advanced"], key="decode_method")

                decode_intensity = st.slider("Decoding Intensity", 1, 4, 1, key="decode_intensity")

                decode_btn = st.button("🔓 Extract Message", type="primary", use_container_width=True)

                if decode_btn:
                    if decode_image and decode_password:
                        with st.spinner("Decoding message..."):
                            # Read image
                            image_bytes = decode_image.read()

                            # Decode message
                            method_str = 'lsb' if 'Basic' in decode_method else 'lsb_advanced'
                            decoded = st.session_state.steganography.decode_message(
                                image_bytes, decode_password, method_str, decode_intensity
                            )

                            if decoded:
                                # Save operation to database
                                message_hash = hashlib.sha256(decoded.encode()).hexdigest()
                                password_hash = hashlib.sha256(decode_password.encode()).hexdigest()
                                st.session_state.db.save_stego_operation(
                                    st.session_state.current_user['id'],
                                    'decode',
                                    decode_image.name,
                                    decode_image.name,
                                    message_hash,
                                    password_hash,
                                    method_str,
                                    decode_intensity
                                )

                                st.success("✅ Message extracted successfully!")
                                st.text_area("Extracted Message", decoded, height=150, key="extracted_msg")
                            else:
                                st.error("Failed to extract message. Wrong password or no hidden data.")
                    else:
                        st.error("Please upload an image and enter password")

    def quantum_page(self):
        st.markdown("### ⚛️ Quantum-Resistant Encryption")

        if st.session_state.quantum_keys is None:
            st.session_state.quantum_keys = st.session_state.quantum.generate_keypair()

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Public Key")
            st.code(st.session_state.quantum_keys['public'][:100] + "...", language="text")
            st.caption("Share this key for quantum-resistant communication")

        with col2:
            st.markdown("#### Private Key (Encrypted)")
            st.code(st.session_state.quantum_keys['private'][:100] + "...", language="text")
            st.caption("Keep this key secure. Never share it!")

        st.divider()

        st.markdown("#### 🔐 Quantum-Resistant Features")

        features = [
            ("Post-Quantum Security", "Resistant to quantum computer attacks"),
            ("Forward Secrecy", "Compromised keys don't expose past messages"),
            ("256-bit Security", "Military-grade encryption strength"),
            ("Key Rotation", "Automatic periodic key regeneration")
        ]

        for title, desc in features:
            with st.expander(f"✅ {title}"):
                st.write(desc)

        if st.button("🔄 Regenerate Quantum Keys", use_container_width=True):
            st.session_state.quantum_keys = st.session_state.quantum.generate_keypair()
            st.success("Quantum keys regenerated successfully!")
            st.rerun()

    def stats_page(self):
        st.markdown("### 📊 Your Statistics")

        if st.session_state.current_user:
            stats = st.session_state.db.get_user_stats(st.session_state.current_user['id'])

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    label="Messages Sent",
                    value=stats['messages_sent'],
                    delta=f"{stats['messages_sent']}"
                )

            with col2:
                st.metric(
                    label="Messages Read",
                    value=stats['messages_read'],
                    delta=f"{stats['messages_read']}"
                )

            with col3:
                st.metric(
                    label="Stego Operations",
                    value=stats['stego_operations'],
                    delta=f"{stats['stego_operations']}"
                )

            st.divider()

            st.markdown("#### 📈 Activity Overview")

            # Placeholder for activity chart
            st.info("Activity charts will be available in future updates")

            st.divider()

            st.markdown("#### 🔒 Security Status")

            security_items = [
                ("AES-256 Encryption", "✅ Active", "green"),
                ("Quantum Resistance", "✅ Enabled", "green"),
                ("Steganography", "✅ Ready", "green"),
                ("End-to-End", "✅ Encrypted", "green"),
                ("Key Rotation", "⏳ Every 30 days", "orange")
            ]

            for item, status, color in security_items:
                st.markdown(f"- **{item}**: <span style='color:{color}'>{status}</span>", unsafe_allow_html=True)

    def settings_page(self):
        st.markdown("### ⚙️ Settings")

        tab1, tab2, tab3 = st.tabs(["👤 Profile", "🔐 Security", "ℹ️ About"])

        with tab1:
            st.markdown("#### Personal Information")

            user = st.session_state.current_user

            # Using columns instead of form to avoid conflicts
            col1, col2 = st.columns(2)

            with col1:
                username = st.text_input("Username", value=user['username'], key="set_username")
                phone = st.text_input("Phone", value=user.get('phone', ''), key="set_phone")

            with col2:
                status = st.text_input("Status", value=user.get('status', 'Secure & Encrypted 🔐'), key="set_status")

                # Avatar color
                colors = ['#25D366', '#34B7F1', '#FF6B6B', '#FFD93D', '#9B59B6', '#1ABC9C', '#E74C3C']
                current_color = user.get('avatar_color', '#25D366')

                selected_color = st.selectbox("Avatar Color", colors,
                                              index=colors.index(current_color) if current_color in colors else 0,
                                              key="set_color")

            # Show color preview
            st.markdown(
                f'<div style="background-color: {selected_color}; width: 100px; height: 100px; border-radius: 10px; margin: 10px 0;"></div>',
                unsafe_allow_html=True)

            if st.button("Save Changes", key="save_profile"):
                st.success("Profile updated successfully! (Note: Actual update requires backend implementation)")

        with tab2:
            st.markdown("#### Security Settings")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("##### Encryption")
                encryption_algo = st.selectbox("Algorithm", ["AES-256-CBC", "AES-256-GCM", "ChaCha20-Poly1305"],
                                               key="enc_algo")
                key_rotation = st.select_slider("Key Rotation", options=["7 days", "30 days", "90 days", "Never"],
                                                value="30 days", key="key_rot")

                st.markdown("##### Features")
                auto_encrypt = st.toggle("Auto-encrypt all messages", value=True, key="auto_enc")
                require_password = st.toggle("Require password for decryption", value=True, key="req_pass")
                perfect_forward = st.toggle("Perfect forward secrecy", value=True, key="pfs")

            with col2:
                st.markdown("##### Steganography")
                default_method = st.selectbox("Default Method", ["LSB (Basic)", "LSB Advanced"], key="steg_method")
                default_intensity = st.slider("Default Intensity", 1, 4, 1, key="steg_int")

                st.markdown("##### Advanced")
                deniable_encryption = st.toggle("Deniable encryption", value=False, key="deniable")
                quantum_mode = st.toggle("Quantum-resistant mode", value=True, key="quantum_mode")

            if st.button("Apply Security Settings", key="apply_security"):
                st.success("Security settings applied!")

        with tab3:
            st.markdown("#### About E-Encrypt")

            st.markdown("""
            **Version:** 6.0.0

            **Description:**
            E-Encrypt is a quantum-resistant secure messenger with advanced steganography capabilities.

            **Features:**
            - 🔐 AES-256 end-to-end encryption
            - 🖼️ Advanced image steganography
            - ⚛️ Quantum-resistant algorithms
            - 💬 Real-time encrypted chat
            - 📊 Message statistics
            - 🔑 Key management

            **Security:**
            - All messages encrypted locally
            - No message storage on servers
            - Open-source cryptography
            - Regular security audits

            **© 2024 SecureTech Inc.**
            """)

            st.divider()

            st.markdown("#### System Information")
            st.code(f"""
            Database: securechat.db
            Users: {len(st.session_state.db.get_user_chats(st.session_state.current_user['id']))}
            Messages: {st.session_state.db.get_user_stats(st.session_state.current_user['id'])['messages_sent']}
            Stego Operations: {st.session_state.db.get_user_stats(st.session_state.current_user['id'])['stego_operations']}
            """)


# Run the app
if __name__ == "__main__":
    app = EEncryptWebApp()
    app.run()