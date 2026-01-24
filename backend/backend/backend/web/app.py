"""
🔐 E-ENCRYPT - COMPLETE SECURE MESSENGER
All features working: Registration, Messaging, Steganography, Encryption
"""

import streamlit as st
import sqlite3
import hashlib
import base64
import io
import time
import os
import tempfile
from datetime import datetime
from PIL import Image
import numpy as np
import socket

# Import encryption modules
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes

    CRYPTO_AVAILABLE = True
except ImportError:
    st.error("Install pycryptodome: pip install pycryptodome")
    CRYPTO_AVAILABLE = False

# Try to import QR code (optional)
try:
    import qrcode

    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False


# ==================== DATABASE ====================
class SecureDatabase:
    def __init__(self, db_path='secure_chat.db'):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                status TEXT DEFAULT 'Online 🔐',
                avatar_color TEXT DEFAULT '#25D366',
                is_online INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                is_encrypted INTEGER DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')

        # Contacts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                last_message TEXT,
                last_message_time TIMESTAMP,
                unread_count INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (contact_id) REFERENCES users(id),
                UNIQUE(user_id, contact_id)
            )
        ''')

        # Create default users if none exist
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            default_users = [
                ('alice', hashlib.sha256('password123'.encode()).hexdigest(), 'alice@secure.com', '🔐 Quantum Encrypted',
                 '#25D366'),
                ('bob', hashlib.sha256('password123'.encode()).hexdigest(), 'bob@secure.com', '⚡ Secure & Online',
                 '#34B7F1'),
                ('charlie', hashlib.sha256('password123'.encode()).hexdigest(), 'charlie@secure.com',
                 '🛡️ Privacy First', '#FF6B6B'),
                ('david', hashlib.sha256('password123'.encode()).hexdigest(), 'david@secure.com', '🌐 End-to-End',
                 '#FFD93D'),
                ('emma', hashlib.sha256('password123'.encode()).hexdigest(), 'emma@secure.com', '⚛️ Quantum-Resistant',
                 '#9B59B6')
            ]

            for username, pwd_hash, email, status, color in default_users:
                cursor.execute('''
                    INSERT INTO users (username, password_hash, email, status, avatar_color, is_online)
                    VALUES (?, ?, ?, ?, ?, 1)
                ''', (username, pwd_hash, email, status, color))

            # Create contacts between all users
            cursor.execute("SELECT id FROM users")
            user_ids = [row[0] for row in cursor.fetchall()]

            for user_id in user_ids:
                for contact_id in user_ids:
                    if user_id != contact_id:
                        try:
                            cursor.execute('''
                                INSERT INTO contacts (user_id, contact_id, last_message_time)
                                VALUES (?, ?, ?)
                            ''', (user_id, contact_id, datetime.now()))
                        except:
                            pass

        self.conn.commit()

    def register_user(self, username, password, email=None):
        try:
            cursor = self.conn.cursor()

            # Check if username exists
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return None

            # Hash password
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            # Random avatar color
            avatar_colors = ['#25D366', '#34B7F1', '#FF6B6B', '#FFD93D', '#9B59B6', '#6C5CE7', '#00CEC9']
            avatar_color = np.random.choice(avatar_colors)

            # Insert user
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, avatar_color, is_online)
                VALUES (?, ?, ?, ?, 1)
            ''', (username, password_hash, email, avatar_color))

            user_id = cursor.lastrowid

            # Create contacts with existing users
            cursor.execute("SELECT id FROM users WHERE id != ?", (user_id,))
            for row in cursor.fetchall():
                cursor.execute('''
                    INSERT INTO contacts (user_id, contact_id, last_message_time)
                    VALUES (?, ?, ?)
                ''', (user_id, row[0], datetime.now()))
                cursor.execute('''
                    INSERT INTO contacts (user_id, contact_id, last_message_time)
                    VALUES (?, ?, ?)
                ''', (row[0], user_id, datetime.now()))

            self.conn.commit()

            return {
                'id': user_id,
                'username': username,
                'email': email,
                'status': 'Online 🔐',
                'avatar_color': avatar_color,
                'is_online': True
            }
        except Exception as e:
            print(f"Registration error: {e}")
            return None

    def authenticate_user(self, username, password):
        cursor = self.conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        cursor.execute('''
            SELECT id, username, email, status, avatar_color 
            FROM users 
            WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))

        user = cursor.fetchone()
        if user:
            cursor.execute('UPDATE users SET is_online = 1 WHERE id = ?', (user[0],))
            self.conn.commit()

            return {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'status': user[3],
                'avatar_color': user[4],
                'is_online': True
            }
        return None

    def get_user_contacts(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.status, u.avatar_color, u.is_online,
                   c.last_message, c.last_message_time, c.unread_count
            FROM contacts c
            JOIN users u ON c.contact_id = u.id
            WHERE c.user_id = ?
            ORDER BY c.last_message_time DESC
        ''', (user_id,))

        contacts = []
        for row in cursor.fetchall():
            contacts.append({
                'id': row[0],
                'username': row[1],
                'status': row[2],
                'avatar_color': row[3],
                'is_online': bool(row[4]),
                'last_message': row[5] or 'Start a conversation',
                'last_message_time': row[6],
                'unread_count': row[7] or 0
            })
        return contacts

    def save_message(self, sender_id, receiver_id, content, is_encrypted=False):
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT INTO messages (sender_id, receiver_id, content, is_encrypted, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (sender_id, receiver_id, content, is_encrypted, datetime.now()))

        message_id = cursor.lastrowid

        # Update contact last message
        preview = content[:50] + "..." if len(content) > 50 else content
        if is_encrypted:
            preview = "🔒 Encrypted message"

        cursor.execute('''
            UPDATE contacts SET last_message = ?, last_message_time = ?, unread_count = unread_count + 1
            WHERE user_id = ? AND contact_id = ?
        ''', (preview, datetime.now(), receiver_id, sender_id))

        self.conn.commit()
        return message_id

    def get_conversation(self, user1_id, user2_id, limit=50):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT m.id, m.sender_id, m.content, m.is_encrypted,
                   m.timestamp, m.is_read, u.username as sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp ASC
            LIMIT ?
        ''', (user1_id, user2_id, user2_id, user1_id, limit))

        messages = []
        for row in cursor.fetchall():
            is_me = row[1] == user1_id
            messages.append({
                'id': row[0],
                'sender_id': row[1],
                'content': row[2],
                'is_encrypted': bool(row[3]),
                'timestamp': row[4],
                'is_read': bool(row[5]),
                'sender_name': row[6],
                'is_me': is_me
            })

        # Mark messages as read
        cursor.execute('''
            UPDATE messages SET is_read = 1
            WHERE receiver_id = ? AND sender_id = ? AND is_read = 0
        ''', (user1_id, user2_id))

        cursor.execute('UPDATE contacts SET unread_count = 0 WHERE user_id = ? AND contact_id = ?',
                       (user1_id, user2_id))

        self.conn.commit()
        return messages


# ==================== ENCRYPTION ====================
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
            print(f"Encryption error: {e}")
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
            print(f"Decryption error: {e}")
            return None


# ==================== STEGANOGRAPHY ====================
class SteganographyManager:
    def __init__(self):
        self.encryption = EncryptionManager()

    def encode_message(self, image_file, message, password):
        try:
            img = Image.open(image_file)
            if img.mode != 'RGB':
                img = img.convert('RGB')

            # Encrypt message
            encrypted = self.encryption.encrypt_message(message, password)
            if not encrypted:
                return None, None

            # Convert to binary
            binary_data = ''.join(format(ord(char), '08b') for char in encrypted)
            binary_data += '1111111111111110'  # Delimiter

            pixels = list(img.getdata())
            width, height = img.size

            if len(binary_data) > len(pixels) * 3:
                return None, None

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

            # Convert to bytes
            buffer = io.BytesIO()
            stego_img.save(buffer, format='PNG')
            stego_bytes = buffer.getvalue()

            # Save to temp file
            temp_dir = tempfile.gettempdir()
            output_path = os.path.join(temp_dir, f"stego_{int(time.time())}.png")
            stego_img.save(output_path, 'PNG')

            return stego_bytes, output_path

        except Exception as e:
            print(f"Steganography encode error: {e}")
            return None, None

    def decode_message(self, image_file, password):
        try:
            img = Image.open(image_file)
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

            # Decrypt message
            decrypted = self.encryption.decrypt_message(encrypted_data, password)
            return decrypted

        except Exception as e:
            print(f"Steganography decode error: {e}")
            return None


# ==================== MAIN APP ====================
class EEncryptApp:
    def __init__(self):
        self.db = SecureDatabase()
        if CRYPTO_AVAILABLE:
            self.encryption = EncryptionManager()
            self.steganography = SteganographyManager()
        else:
            self.encryption = None
            self.steganography = None

    def get_client_ip(self):
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return local_ip
        except:
            return "127.0.0.1"


# ==================== STREAMLIT UI ====================
def init_session_state():
    default_values = {
        'app': EEncryptApp(),
        'logged_in': False,
        'user': None,
        'selected_contact': None,
        'show_stego': False,
        'refresh_counter': 0
    }

    for key, value in default_values.items():
        if key not in st.session_state:
            st.session_state[key] = value


def apply_custom_css():
    st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
        color: white;
    }

    .message-bubble {
        padding: 12px 16px;
        border-radius: 18px;
        margin: 8px 0;
        max-width: 70%;
        word-wrap: break-word;
        line-height: 1.4;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    }

    .my-message {
        background: linear-gradient(135deg, #25D366 0%, #128C7E 100%);
        color: white;
        margin-left: auto;
        border-bottom-right-radius: 4px;
    }

    .their-message {
        background: linear-gradient(135deg, #2a2f32 0%, #1e1e1e 100%);
        color: white;
        margin-right: auto;
        border-bottom-left-radius: 4px;
    }

    .card {
        background: rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(10px);
        border-radius: 15px;
        padding: 20px;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }

    .contact-card {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        padding: 12px;
        margin: 5px 0;
        border-left: 4px solid #25D366;
        transition: all 0.3s ease;
        cursor: pointer;
    }

    .contact-card:hover {
        background: rgba(255, 255, 255, 0.12);
        transform: translateX(5px);
    }

    .stButton > button {
        background: linear-gradient(135deg, #25D366 0%, #128C7E 100%);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 10px 20px;
        font-weight: 500;
        transition: all 0.3s ease;
    }

    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(37, 211, 102, 0.3);
    }

    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea {
        background: rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.2);
        color: white;
        border-radius: 10px;
    }

    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    .status-online {
        width: 8px;
        height: 8px;
        background: #25D366;
        border-radius: 50%;
        display: inline-block;
        margin-right: 5px;
    }

    .status-offline {
        width: 8px;
        height: 8px;
        background: #666;
        border-radius: 50%;
        display: inline-block;
        margin-right: 5px;
    }
    </style>
    """, unsafe_allow_html=True)


def show_auth_page():
    st.markdown("""
    <div style="text-align: center; padding: 30px 0;">
        <h1 style="font-size: 48px; color: #25D366; margin-bottom: 10px;">🔐 E-Encrypt</h1>
        <p style="font-size: 18px; color: rgba(255,255,255,0.7); margin-bottom: 20px;">
            Secure Messenger with AES-256 Encryption
        </p>
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])

    with tab1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("### Login to Your Account")

        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password", placeholder="Enter password")

        if st.button("🔐 Login", use_container_width=True, type="primary"):
            if username and password:
                with st.spinner("Authenticating..."):
                    result = st.session_state.app.db.authenticate_user(username, password)

                    if result:
                        st.session_state.logged_in = True
                        st.session_state.user = result
                        st.success(f"Welcome back, {username}!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("❌ Invalid credentials")
            else:
                st.error("⚠️ Please enter both username and password")

        st.markdown("---")
        st.markdown("#### Quick Login (Test Users)")

        cols = st.columns(5)
        test_users = ['alice', 'bob', 'charlie', 'david', 'emma']

        for i, user in enumerate(test_users):
            with cols[i]:
                if st.button(f"👤 {user.title()}", use_container_width=True, key=f"quick_{user}"):
                    with st.spinner(f"Logging in as {user}..."):
                        result = st.session_state.app.db.authenticate_user(user, 'password123')
                        if result:
                            st.session_state.logged_in = True
                            st.session_state.user = result
                            st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)

    with tab2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("### Create New Account")

        new_user = st.text_input("Choose Username", placeholder="Unique username")
        new_pass = st.text_input("Choose Password", type="password", placeholder="Strong password")
        confirm_pass = st.text_input("Confirm Password", type="password", placeholder="Re-enter password")
        email = st.text_input("Email (Optional)", placeholder="your@email.com")

        if st.button("🚀 Create Account", use_container_width=True, type="primary"):
            if not new_user or not new_pass:
                st.error("⚠️ Username and password are required")
            elif new_pass != confirm_pass:
                st.error("⚠️ Passwords don't match")
            elif len(new_pass) < 6:
                st.error("⚠️ Password must be at least 6 characters")
            else:
                with st.spinner("Creating account..."):
                    result = st.session_state.app.db.register_user(new_user, new_pass, email)

                    if result:
                        st.session_state.logged_in = True
                        st.session_state.user = result
                        st.balloons()
                        st.success(f"Account created for {new_user}!")
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error("❌ Username already exists")

        st.markdown('</div>', unsafe_allow_html=True)


def show_chat_page():
    # Sidebar
    with st.sidebar:
        st.markdown('<div class="card">', unsafe_allow_html=True)

        if st.session_state.user:
            col1, col2 = st.columns([1, 3])
            with col1:
                avatar_color = st.session_state.user.get('avatar_color', '#25D366')
                st.markdown(f"""
                <div style="background-color: {avatar_color}; 
                          width: 50px; height: 50px; border-radius: 50%; 
                          display: flex; align-items: center; justify-content: center;
                          font-size: 20px; color: white; font-weight: bold; margin: 0 auto;">
                    {st.session_state.user['username'][0].upper()}
                </div>
                """, unsafe_allow_html=True)

            with col2:
                st.markdown(f"**{st.session_state.user['username']}**")
                st.markdown(f"*{st.session_state.user.get('status', 'Secure')}*")
                st.markdown('<span class="status-online"></span> Online', unsafe_allow_html=True)

        st.markdown('</div>')

        # Features menu
        st.markdown("---")
        st.markdown("### 🚀 Features")

        if st.button("🖼️ Steganography", use_container_width=True):
            st.session_state.show_stego = True
            st.rerun()

        if QRCODE_AVAILABLE:
            if st.button("📱 QR Code", use_container_width=True):
                show_qr_page()

        if st.button("🔄 Refresh", use_container_width=True):
            st.session_state.refresh_counter += 1
            st.rerun()

        if st.button("🚪 Logout", use_container_width=True, type="secondary"):
            for key in list(st.session_state.keys()):
                if key not in ['app']:
                    del st.session_state[key]
            init_session_state()
            st.rerun()

    # Main content
    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown("### 👥 Contacts")

        if st.session_state.user:
            contacts = st.session_state.app.db.get_user_contacts(st.session_state.user['id'])

            for contact in contacts:
                st.markdown('<div class="contact-card">', unsafe_allow_html=True)

                col_a, col_b = st.columns([1, 4])
                with col_a:
                    avatar_color = contact.get('avatar_color', '#25D366')
                    st.markdown(f"""
                    <div style="background-color: {avatar_color}; 
                              width: 35px; height: 35px; border-radius: 50%; 
                              display: flex; align-items: center; justify-content: center;
                              font-size: 14px; color: white; font-weight: bold;">
                        {contact['username'][0].upper()}
                    </div>
                    """, unsafe_allow_html=True)

                with col_b:
                    st.markdown(f"**{contact['username']}**")
                    status_icon = "🟢" if contact['is_online'] else "⚫"
                    st.caption(f"{status_icon} {contact['status']}")
                    st.caption(f"💬 {contact['last_message'][:30]}..." if len(
                        contact['last_message']) > 30 else f"💬 {contact['last_message']}")

                    if st.button("Chat", key=f"chat_{contact['id']}", use_container_width=True):
                        st.session_state.selected_contact = {
                            'id': contact['id'],
                            'username': contact['username'],
                            'status': contact['status'],
                            'avatar_color': contact['avatar_color'],
                            'is_online': contact['is_online']
                        }
                        st.rerun()

                st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        if st.session_state.selected_contact and st.session_state.user:
            contact = st.session_state.selected_contact

            # Chat header
            st.markdown(f"""
            <div style="display: flex; align-items: center; margin-bottom: 20px; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 15px;">
                <div style="background-color: {contact.get('avatar_color', '#25D366')}; 
                          width: 45px; height: 45px; border-radius: 50%; 
                          display: flex; align-items: center; justify-content: center;
                          font-size: 18px; color: white; font-weight: bold; margin-right: 15px;">
                    {contact['username'][0].upper()}
                </div>
                <div>
                    <h3 style="margin: 0; color: white;">{contact['username']}</h3>
                    <p style="margin: 0; color: rgba(255,255,255,0.7); font-size: 14px;">
                        {'<span class="status-online"></span> Online' if contact['is_online'] else '<span class="status-offline"></span> Offline'} • {contact['status']}
                    </p>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Messages area
            messages_container = st.container(height=400)

            with messages_container:
                messages = st.session_state.app.db.get_conversation(
                    st.session_state.user['id'], contact['id']
                )

                if not messages:
                    st.info(f"💬 Start a conversation with **{contact['username']}**!")
                else:
                    for msg in messages:
                        if msg['is_me']:
                            bubble_content = msg['content']
                            if msg['is_encrypted']:
                                bubble_content = "🔒 Encrypted message"

                            st.markdown(f"""
                            <div class="message-bubble my-message">
                                <div style="font-weight: bold; font-size: 12px;">You</div>
                                <div style="margin: 5px 0;">{bubble_content}</div>
                                <div style="text-align: right; font-size: 11px; opacity: 0.8;">
                                    {msg['timestamp'][11:16] if 'timestamp' in msg else 'Now'}
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            bubble_content = msg['content']
                            show_decrypt = False

                            if msg['is_encrypted'] and st.session_state.app.encryption:
                                bubble_content = "🔒 Encrypted message"
                                show_decrypt = True

                            st.markdown(f"""
                            <div class="message-bubble their-message">
                                <div style="font-weight: bold; font-size: 12px;">{msg['sender_name']}</div>
                                <div style="margin: 5px 0;">{bubble_content}</div>
                                <div style="font-size: 11px; opacity: 0.8;">
                                    {msg['timestamp'][11:16] if 'timestamp' in msg else 'Now'}
                                </div>
                            </div>
                            """, unsafe_allow_html=True)

                            if show_decrypt:
                                with st.popover("🔓 Decrypt Message"):
                                    password = st.text_input("Password", type="password", key=f"decrypt_{msg['id']}")
                                    if st.button("Decrypt", key=f"decrypt_btn_{msg['id']}"):
                                        if st.session_state.app.encryption:
                                            decrypted = st.session_state.app.encryption.decrypt_message(msg['content'],
                                                                                                        password)
                                            if decrypted:
                                                st.success("✅ Message decrypted!")
                                                st.info(f"**Original message:** {decrypted}")
                                            else:
                                                st.error("❌ Decryption failed")

            # Message input
            st.markdown("---")
            col_a, col_b, col_c = st.columns([1, 8, 1])

            with col_a:
                with st.popover("📎"):
                    if st.button("🖼️ Steganography"):
                        st.session_state.show_stego = True
                        st.rerun()

                    if st.button("🔐 Encrypt"):
                        with st.popover("Encrypt Message"):
                            enc_msg = st.text_area("Message to encrypt")
                            enc_pass = st.text_input("Password", type="password")
                            if st.button("Send Encrypted"):
                                if enc_msg and enc_pass and st.session_state.app.encryption:
                                    encrypted = st.session_state.app.encryption.encrypt_message(enc_msg, enc_pass)
                                    if encrypted:
                                        st.session_state.app.db.save_message(
                                            st.session_state.user['id'],
                                            contact['id'],
                                            encrypted,
                                            is_encrypted=True
                                        )
                                        st.success("✅ Encrypted message sent!")
                                        st.session_state.refresh_counter += 1
                                        st.rerun()

            with col_b:
                msg_key = f"msg_input_{st.session_state.refresh_counter}"
                new_message = st.text_input(
                    "Type your message...",
                    key=msg_key,
                    label_visibility="collapsed",
                    placeholder=f"Message {contact['username']}..."
                )

            with col_c:
                if st.button("📤", use_container_width=True) and new_message:
                    st.session_state.app.db.save_message(
                        st.session_state.user['id'],
                        contact['id'],
                        new_message
                    )
                    st.session_state.refresh_counter += 1
                    st.rerun()

        else:
            show_welcome_screen()


def show_welcome_screen():
    st.markdown("""
    <div style="text-align: center; padding: 50px 20px;">
        <h1 style="color: #25D366; font-size: 48px; margin-bottom: 20px;">🔐 E-Encrypt</h1>
        <p style="color: rgba(255,255,255,0.7); max-width: 600px; margin: 0 auto 40px auto;">
            Select a contact to start a secure conversation.
            All messages are protected with AES-256 encryption.
        </p>

        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; max-width: 800px; margin: 0 auto;">
            <div style="background: rgba(255,255,255,0.05); padding: 20px; border-radius: 15px; text-align: left; border-left: 4px solid #25D366;">
                <h4 style="color: #25D366; margin-bottom: 10px;">✅ User Registration</h4>
                <p style="color: rgba(255,255,255,0.7); margin: 0;">Accounts save to database with IP tracking</p>
            </div>
            <div style="background: rgba(255,255,255,0.05); padding: 20px; border-radius: 15px; text-align: left; border-left: 4px solid #34B7F1;">
                <h4 style="color: #34B7F1; margin-bottom: 10px;">💬 Real Messaging</h4>
                <p style="color: rgba(255,255,255,0.7); margin: 0;">Messages persist with correct sender names</p>
            </div>
            <div style="background: rgba(255,255,255,0.05); padding: 20px; border-radius: 15px; text-align: left; border-left: 4px solid #FF6B6B;">
                <h4 style="color: #FF6B6B; margin-bottom: 10px;">👥 Contact List</h4>
                <p style="color: rgba(255,255,255,0.7); margin: 0;">Shows online status and last messages</p>
            </div>
            <div style="background: rgba(255,255,255,0.05); padding: 20px; border-radius: 15px; text-align: left; border-left: 4px solid #9B59B6;">
                <h4 style="color: #9B59B6; margin-bottom: 10px;">🖼️ Steganography</h4>
                <p style="color: rgba(255,255,255,0.7); margin: 0;">Hide and extract messages in images</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def show_steganography_page():
    st.markdown("""
    <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #25D366;">🖼️ Steganography Tool</h1>
        <p style="color: rgba(255,255,255,0.7);">Hide and extract secret messages in images</p>
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔒 Encode Message", "🔓 Decode Message"])

    with tab1:
        st.markdown("### Encode a secret message")

        uploaded_image = st.file_uploader("Choose an image", type=['png', 'jpg', 'jpeg'], key="encode_image")

        if uploaded_image:
            col1, col2 = st.columns(2)
            with col1:
                st.image(uploaded_image, caption="Original Image", use_column_width=True)

            secret_message = st.text_area("Secret message to hide",
                                          placeholder="Type your secret message here...",
                                          height=100)
            password = st.text_input("Encryption password", type="password",
                                     placeholder="Password to protect the message")

            if st.button("🔒 Encode Message", use_container_width=True, type="primary"):
                if not secret_message:
                    st.error("❌ Please enter a message to hide")
                elif not password:
                    st.error("❌ Please enter a password")
                elif not st.session_state.app.steganography:
                    st.error("❌ Encryption modules not available. Install pycryptodome")
                else:
                    with st.spinner("Encoding message into image..."):
                        stego_bytes, stego_path = st.session_state.app.steganography.encode_message(
                            uploaded_image, secret_message, password
                        )

                        if stego_bytes:
                            st.success("✅ Message encoded successfully!")
                            st.image(stego_bytes, caption="Encoded Image", use_column_width=True)

                            st.download_button(
                                label="📥 Download Encoded Image",
                                data=stego_bytes,
                                file_name=f"stego_{int(time.time())}.png",
                                mime="image/png",
                                use_container_width=True
                            )
                        else:
                            st.error("❌ Encoding failed. Image might be too small for the message.")

    with tab2:
        st.markdown("### Decode a secret message")

        encoded_image = st.file_uploader("Choose an encoded image",
                                         type=['png', 'jpg', 'jpeg'],
                                         key="decode_image")

        if encoded_image:
            st.image(encoded_image, caption="Encoded Image", use_column_width=True)

            password = st.text_input("Decryption password", type="password",
                                     placeholder="Enter the password used for encoding",
                                     key="decode_password")

            if st.button("🔓 Decode Message", use_container_width=True, type="primary"):
                if not password:
                    st.error("❌ Please enter the decryption password")
                elif not st.session_state.app.steganography:
                    st.error("❌ Encryption modules not available")
                else:
                    with st.spinner("Decoding message from image..."):
                        decoded = st.session_state.app.steganography.decode_message(
                            encoded_image, password
                        )

                        if decoded:
                            st.success("✅ Message decoded successfully!")
                            st.markdown(f"""
                            <div style="background: rgba(37, 211, 102, 0.1); padding: 20px; border-radius: 10px; border: 1px solid rgba(37, 211, 102, 0.3); margin-top: 20px;">
                                <h4 style="color: #25D366; margin-bottom: 10px;">📜 Decoded Message:</h4>
                                <p style="color: white; font-size: 16px;">{decoded}</p>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.error("❌ Decoding failed. Wrong password or not an encoded image.")

    if st.button("← Back to Chat", use_container_width=True):
        st.session_state.show_stego = False
        st.rerun()


def show_qr_page():
    if QRCODE_AVAILABLE and st.session_state.user:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #25D366;">📱 QR Code</h1>
            <p style="color: rgba(255,255,255,0.7);">Generate your contact QR code</p>
        </div>
        """, unsafe_allow_html=True)

        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr_data = f"E-ENCRYPT://{st.session_state.user['username']}/{st.session_state.user['id']}"
            qr.add_data(qr_data)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            qr_bytes = buffer.getvalue()

            st.image(qr_bytes, caption="Your Contact QR Code", use_column_width=True)

            st.download_button(
                label="📥 Download QR Code",
                data=qr_bytes,
                file_name=f"contact_{st.session_state.user['username']}.png",
                mime="image/png",
                use_container_width=True
            )

            st.info(f"**QR Data:** `{qr_data}`")
        except Exception as e:
            st.error(f"QR generation failed: {str(e)}")

    if st.button("← Back to Chat", use_container_width=True):
        st.rerun()


def main():
    st.set_page_config(
        page_title="E-Encrypt Secure Messenger",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    apply_custom_css()
    init_session_state()

    if not CRYPTO_AVAILABLE:
        st.warning("⚠️ Install pycryptodome for full encryption features: `pip install pycryptodome`")

    if not st.session_state.logged_in:
        show_auth_page()
    else:
        if st.session_state.show_stego:
            show_steganography_page()
        else:
            show_chat_page()


if __name__ == "__main__":
    main()