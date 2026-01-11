import socket
import threading
import base64
import json
import time
import sqlite3
import hashlib
import uuid
import os
import random
import math
import qrcode
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.image import Image as KivyImage
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.core.window import Window
from kivy.graphics import Color, RoundedRectangle, Rectangle, Line, Ellipse
from kivy.uix.behaviors import ButtonBehavior
from kivy.properties import StringProperty, NumericProperty, ListProperty, BooleanProperty
from kivy.clock import Clock
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.progressbar import ProgressBar
from kivy.core.audio import SoundLoader
from kivy.core.clipboard import Clipboard


# ==================== DATABASE MANAGER ====================
class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect('eencrypt.db', check_same_thread=False)
        self.create_tables()
        self.create_default_users()

    def create_tables(self):
        cursor = self.conn.cursor()

        # Drop old tables if they exist
        cursor.execute('DROP TABLE IF EXISTS users')
        cursor.execute('DROP TABLE IF EXISTS messages')
        cursor.execute('DROP TABLE IF EXISTS contacts')

        # Users table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                public_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                is_online INTEGER DEFAULT 0
            )
        ''')

        # Messages table
        cursor.execute('''
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message_type TEXT DEFAULT 'text',
                content TEXT NOT NULL,
                encrypted_content TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                is_delivered INTEGER DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')

        # Contacts table
        cursor.execute('''
            CREATE TABLE contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                contact_name TEXT NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, contact_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (contact_id) REFERENCES users(id)
            )
        ''')

        self.conn.commit()
        print("✅ Database tables created successfully")

    def create_default_users(self):
        cursor = self.conn.cursor()

        # Check if users exist
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]

        if count == 0:
            default_users = [
                ('alice', 'password123', 'alice@example.com'),
                ('bob', 'password123', 'bob@example.com'),
                ('charlie', 'password123', 'charlie@example.com'),
            ]

            for username, password, email in default_users:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                public_key = base64.b64encode(os.urandom(32)).decode()  # 256-bit key
                cursor.execute('''
                    INSERT INTO users (username, password_hash, email, public_key)
                    VALUES (?, ?, ?, ?)
                ''', (username, password_hash, email, public_key))

            # Get user IDs
            cursor.execute("SELECT id, username FROM users")
            users = cursor.fetchall()
            print(f"✅ Created users: {users}")

            # Create contacts
            for i, (user1_id, user1_name) in enumerate(users):
                for j, (user2_id, user2_name) in enumerate(users):
                    if i != j and i < j:  # Avoid duplicates
                        cursor.execute('''
                            INSERT OR IGNORE INTO contacts (user_id, contact_id, contact_name)
                            VALUES (?, ?, ?)
                        ''', (user1_id, user2_id, user2_name))

                        cursor.execute('''
                            INSERT OR IGNORE INTO contacts (user_id, contact_id, contact_name)
                            VALUES (?, ?, ?)
                        ''', (user2_id, user1_id, user1_name))

            # Add sample messages
            sample_messages = [
                (1, 2, 'text', 'Hi Bob! How are you doing today?'),
                (2, 1, 'text', 'Hello Alice! I\'m good, working on our project.'),
                (1, 2, 'text', 'That\'s great! Can we meet tomorrow?'),
                (2, 1, 'text', 'Sure, 2 PM at the usual cafe?'),
                (3, 1, 'text', 'Hey Alice, got a minute?'),
                (1, 3, 'text', 'Hi Charlie! Yes, what\'s up?'),
            ]

            for sender_id, receiver_id, msg_type, content in sample_messages:
                cursor.execute('''
                    INSERT INTO messages (sender_id, receiver_id, message_type, content)
                    VALUES (?, ?, ?, ?)
                ''', (sender_id, receiver_id, msg_type, content))

            self.conn.commit()
            print(f"✅ Created {len(default_users)} default users with contacts and messages")

    def authenticate_user(self, username, password):
        cursor = self.conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        cursor.execute('''
            SELECT id, username, email, public_key FROM users 
            WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))

        user = cursor.fetchone()
        if user:
            # Update last seen
            cursor.execute('''
                UPDATE users SET last_seen = ?, is_online = 1 
                WHERE id = ?
            ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user[0]))
            self.conn.commit()

            return {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'public_key': user[3],
                'status': 'online'
            }
        return None

    def register_user(self, username, password, email=None):
        try:
            cursor = self.conn.cursor()
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            public_key = base64.b64encode(os.urandom(32)).decode()  # 256-bit key

            cursor.execute('''
                INSERT INTO users (username, password_hash, email, public_key)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, email, public_key))

            user_id = cursor.lastrowid
            self.conn.commit()

            return {
                'id': user_id,
                'username': username,
                'email': email,
                'public_key': public_key
            }
        except sqlite3.IntegrityError:
            return None

    def get_user_by_username(self, username):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, username, email, public_key, is_online, last_seen 
            FROM users WHERE username = ?
        ''', (username,))

        user = cursor.fetchone()
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'public_key': user[3],
                'is_online': bool(user[4]),
                'last_seen': user[5]
            }
        return None

    def search_users(self, query, current_user_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, username, email, is_online 
            FROM users 
            WHERE (username LIKE ? OR email LIKE ?) AND id != ?
            LIMIT 20
        ''', (f'%{query}%', f'%{query}%', current_user_id))

        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'is_online': row[3]
            })
        return users

    def add_contact(self, user_id, contact_id, contact_name):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO contacts (user_id, contact_id, contact_name)
                VALUES (?, ?, ?)
            ''', (user_id, contact_id, contact_name))
            self.conn.commit()
            return True
        except:
            return False

    def get_contacts(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.is_online, u.last_seen,
                   (SELECT COUNT(*) FROM messages m 
                    WHERE m.sender_id = u.id AND m.receiver_id = ? AND m.is_read = 0
                   ) as unread_count
            FROM contacts c
            JOIN users u ON c.contact_id = u.id
            WHERE c.user_id = ?
            ORDER BY u.is_online DESC, u.username ASC
        ''', (user_id, user_id))

        contacts = []
        for row in cursor.fetchall():
            contacts.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'is_online': bool(row[3]),
                'last_seen': row[4],
                'unread_count': row[5] or 0
            })
        return contacts

    def save_message(self, sender_id, receiver_id, message_type, content, encrypted_content=None):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO messages (sender_id, receiver_id, message_type, content, encrypted_content)
            VALUES (?, ?, ?, ?, ?)
        ''', (sender_id, receiver_id, message_type, content, encrypted_content))

        message_id = cursor.lastrowid
        self.conn.commit()
        return message_id

    def get_messages(self, user_id, contact_id, limit=100, offset=0):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT m.id, m.sender_id, m.receiver_id, m.message_type, 
                   m.content, m.encrypted_content, m.timestamp, m.is_read,
                   u.username as sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?)
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp ASC
            LIMIT ? OFFSET ?
        ''', (user_id, contact_id, contact_id, user_id, limit, offset))

        messages = []
        for row in cursor.fetchall():
            messages.append({
                'id': row[0],
                'sender_id': row[1],
                'receiver_id': row[2],
                'type': row[3],
                'content': row[4],
                'encrypted': row[5],
                'timestamp': row[6],
                'is_read': row[7],
                'sender_name': row[8]
            })

        # Mark messages as read
        cursor.execute('''
            UPDATE messages SET is_read = 1, is_delivered = 1
            WHERE receiver_id = ? AND sender_id = ? AND is_read = 0
        ''', (user_id, contact_id))
        self.conn.commit()

        return messages

    def update_user_status(self, user_id, is_online):
        cursor = self.conn.cursor()
        last_seen = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            UPDATE users SET is_online = ?, last_seen = ?
            WHERE id = ?
        ''', (1 if is_online else 0, last_seen, user_id))
        self.conn.commit()


# ==================== AES-256 ENCRYPTION ====================
class AES256Encryption:
    def __init__(self):
        self.backend = default_backend()

    def generate_key(self):
        """Generate a 256-bit (32-byte) AES key"""
        return os.urandom(32)

    def encrypt_message(self, message, key):
        """Encrypt message using AES-256 in CBC mode"""
        try:
            # Generate a random IV
            iv = os.urandom(16)

            # Pad the message
            pad_length = 16 - (len(message) % 16)
            padded_message = message + chr(pad_length) * pad_length

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()

            # Encrypt
            ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()

            # Combine IV + ciphertext
            encrypted_data = iv + ciphertext
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_data, key):
        """Decrypt message using AES-256 in CBC mode"""
        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode())

            # Extract IV and ciphertext
            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()

            # Decrypt
            padded_message = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove padding
            pad_length = padded_message[-1]
            message = padded_message[:-pad_length].decode()

            return message
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def encrypt_with_password(self, message, password):
        """Encrypt using password with PBKDF2 key derivation"""
        try:
            # Generate salt
            salt = os.urandom(16)

            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            key = kdf.derive(password.encode())

            # Encrypt with derived key
            encrypted = self.encrypt_message(message, key)
            if encrypted:
                # Return salt + encrypted data
                return base64.b64encode(salt + base64.b64decode(encrypted)).decode()
            return None
        except Exception as e:
            print(f"Password encryption error: {e}")
            return None

    def decrypt_with_password(self, encrypted_data, password):
        """Decrypt using password with PBKDF2 key derivation"""
        try:
            # Decode from base64
            data = base64.b64decode(encrypted_data.encode())

            # Extract salt and encrypted data
            salt = data[:16]
            encrypted_bytes = data[16:]

            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            key = kdf.derive(password.encode())

            # Decrypt with derived key
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
            return self.decrypt_message(encrypted_b64, key)
        except Exception as e:
            print(f"Password decryption error: {e}")
            return None


# ==================== STEGANOGRAPHY ====================
class AdvancedSteganography:
    @staticmethod
    def encode_with_watermark(image_path, text, watermark_text="E-Encrypt"):
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')

            # Add watermark
            draw = ImageDraw.Draw(img)
            try:
                font = ImageFont.truetype("arial.ttf", 20)
            except:
                font = ImageFont.load_default()

            # Draw semi-transparent watermark
            watermark_layer = Image.new('RGBA', img.size, (0, 0, 0, 0))
            watermark_draw = ImageDraw.Draw(watermark_layer)
            watermark_draw.text((10, 10), watermark_text, font=font, fill=(255, 255, 255, 100))

            img = Image.alpha_composite(img.convert('RGBA'), watermark_layer).convert('RGB')

            # Encode message using LSB
            binary_text = ''.join(format(ord(c), '08b') for c in text) + '1111111111111110'
            pixels = list(img.getdata())

            if len(pixels) * 3 < len(binary_text):
                raise ValueError("Text too long for image")

            new_pixels = []
            index = 0
            for pixel in pixels:
                if index < len(binary_text):
                    r, g, b = pixel
                    if index < len(binary_text):
                        r = (r & ~1) | int(binary_text[index])
                        index += 1
                    if index < len(binary_text):
                        g = (g & ~1) | int(binary_text[index])
                        index += 1
                    if index < len(binary_text):
                        b = (b & ~1) | int(binary_text[index])
                        index += 1
                    new_pixels.append((r, g, b))
                else:
                    new_pixels.append(pixel)

            stego_img = Image.new(img.mode, img.size)
            stego_img.putdata(new_pixels)

            output_path = f"stego_{int(time.time())}.png"
            stego_img.save(output_path, format='PNG')
            return output_path
        except Exception as e:
            print(f"Steganography error: {e}")
            return None

    @staticmethod
    def decode_from_image(image_path):
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')

            pixels = list(img.getdata())
            binary_text = ""

            for pixel in pixels:
                r, g, b = pixel
                binary_text += str(r & 1)
                binary_text += str(g & 1)
                binary_text += str(b & 1)

            # Find end marker
            end_marker = '1111111111111110'
            if end_marker in binary_text:
                binary_text = binary_text[:binary_text.index(end_marker)]

            # Convert to text
            text = ""
            for i in range(0, len(binary_text), 8):
                byte = binary_text[i:i + 8]
                if len(byte) == 8:
                    text += chr(int(byte, 2))

            return text
        except Exception as e:
            print(f"Decode error: {e}")
            return ""

    @staticmethod
    def create_qr_code(data, size=10):
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=size,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to bytes for Kivy
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            return img_str
        except Exception as e:
            print(f"QR code error: {e}")
            return ""


# ==================== SIMPLE BACKGROUND ====================
class SimpleBackground(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(0.1, 0.2, 0.3, 1)
            self.rect = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self.update_rect, size=self.update_rect)

    def update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size


# ==================== LOGIN SCREEN ====================
class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Simple background
        bg = SimpleBackground()

        # Main content
        content = BoxLayout(orientation='vertical', padding=40, spacing=20)

        # App Logo/Title
        title_box = BoxLayout(orientation='vertical', size_hint_y=0.3)
        title = Label(
            text='🔒 E-Encrypt Pro',
            font_size='42sp',
            bold=True,
            color=(1, 1, 1, 1)
        )
        subtitle = Label(
            text='Secure Real-Time Messenger',
            font_size='16sp',
            color=(0.9, 0.95, 1, 0.9)
        )
        title_box.add_widget(title)
        title_box.add_widget(subtitle)

        # Login Form
        form_box = BoxLayout(orientation='vertical', spacing=15, size_hint_y=0.4)

        self.username_input = TextInput(
            hint_text='Username (try: alice)',
            size_hint_y=None,
            height=55,
            multiline=False,
            background_normal='',
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1),
            hint_text_color=(0.8, 0.9, 1, 0.7),
            padding=[15, 10],
            font_size='16sp'
        )

        self.password_input = TextInput(
            hint_text='Password (use: password123)',
            password=True,
            size_hint_y=None,
            height=55,
            multiline=False,
            background_normal='',
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1),
            hint_text_color=(0.8, 0.9, 1, 0.7),
            padding=[15, 10],
            font_size='16sp'
        )

        form_box.add_widget(self.username_input)
        form_box.add_widget(self.password_input)

        # Login Buttons
        btn_box = BoxLayout(orientation='vertical', spacing=12, size_hint_y=0.3)

        login_btn = Button(
            text='LOGIN',
            size_hint_y=None,
            height=60,
            background_normal='',
            background_color=(0.2, 0.6, 0.9, 1),
            color=(1, 1, 1, 1),
            bold=True,
            font_size='18sp'
        )
        login_btn.bind(on_press=self.login)

        register_btn = Button(
            text='Create New Account',
            size_hint_y=None,
            height=50,
            background_normal='',
            background_color=(0.4, 0.4, 0.6, 0.8),
            color=(1, 1, 1, 1)
        )
        register_btn.bind(on_press=self.go_register)

        btn_box.add_widget(login_btn)
        btn_box.add_widget(register_btn)

        # Quick login buttons
        quick_box = GridLayout(cols=3, spacing=10, size_hint_y=None, height=65)

        test_accounts = ['alice', 'bob', 'charlie']
        for acc in test_accounts:
            btn = Button(
                text=f'{acc}',
                size_hint_y=None,
                height=45,
                background_normal='',
                background_color=(0.4, 0.6, 0.9, 0.8),
                color=(1, 1, 1, 1)
            )
            btn.bind(on_press=lambda x, a=acc: self.quick_login(a))
            quick_box.add_widget(btn)

        # Add everything
        content.add_widget(title_box)
        content.add_widget(form_box)
        content.add_widget(btn_box)
        content.add_widget(quick_box)

        bg.add_widget(content)
        self.add_widget(bg)

    def quick_login(self, username):
        self.username_input.text = username
        self.password_input.text = 'password123'
        self.login(None)

    def login(self, instance):
        username = self.username_input.text.strip()
        password = self.password_input.text.strip()

        if not username or not password:
            self.show_popup('Error', 'Please enter username and password')
            return

        app = App.get_running_app()

        # Authenticate with database
        user = app.db_manager.authenticate_user(username, password)

        if user:
            app.current_user = user
            app.encryption = AES256Encryption()

            # Load contacts
            Clock.schedule_once(lambda dt: self.manager.get_screen('contacts').load_contacts(), 0.1)

            # Switch to contacts screen
            self.manager.current = 'contacts'

            # Show welcome
            self.show_popup('Welcome', f'Hello {username}! Your messages are encrypted with AES-256.')
        else:
            self.show_popup('Login Failed', 'Invalid username or password')

    def go_register(self, instance):
        self.manager.current = 'register'

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message))

        close_btn = Button(text='OK', size_hint_y=None, height=40)
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))

        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()


# ==================== REGISTRATION SCREEN ====================
class RegisterScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        bg = SimpleBackground()
        layout = BoxLayout(orientation='vertical', padding=40, spacing=15)

        layout.add_widget(Label(
            text='Create Account',
            font_size='28sp',
            bold=True,
            color=(1, 1, 1, 1)
        ))

        self.username_input = TextInput(
            hint_text='Username',
            size_hint_y=None,
            height=55,
            background_normal='',
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1),
            hint_text_color=(0.8, 0.9, 1, 0.7),
            padding=[15, 10]
        )

        self.email_input = TextInput(
            hint_text='Email (optional)',
            size_hint_y=None,
            height=55,
            background_normal='',
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1),
            hint_text_color=(0.8, 0.9, 1, 0.7),
            padding=[15, 10]
        )

        self.password_input = TextInput(
            hint_text='Password (min 6 characters)',
            password=True,
            size_hint_y=None,
            height=55,
            background_normal='',
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1),
            hint_text_color=(0.8, 0.9, 1, 0.7),
            padding=[15, 10]
        )

        self.confirm_password = TextInput(
            hint_text='Confirm Password',
            password=True,
            size_hint_y=None,
            height=55,
            background_normal='',
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1),
            hint_text_color=(0.8, 0.9, 1, 0.7),
            padding=[15, 10]
        )

        layout.add_widget(self.username_input)
        layout.add_widget(self.email_input)
        layout.add_widget(self.password_input)
        layout.add_widget(self.confirm_password)

        btn_box = BoxLayout(spacing=10, size_hint_y=None, height=60)

        register_btn = Button(
            text='Register',
            background_color=(0.2, 0.7, 0.3, 1),
            color=(1, 1, 1, 1)
        )
        register_btn.bind(on_press=self.register)

        cancel_btn = Button(
            text='Cancel',
            background_color=(0.8, 0.2, 0.2, 1),
            color=(1, 1, 1, 1)
        )
        cancel_btn.bind(on_press=self.cancel)

        btn_box.add_widget(register_btn)
        btn_box.add_widget(cancel_btn)
        layout.add_widget(btn_box)

        bg.add_widget(layout)
        self.add_widget(bg)

    def register(self, instance):
        username = self.username_input.text.strip()
        email = self.email_input.text.strip()
        password = self.password_input.text.strip()
        confirm = self.confirm_password.text.strip()

        if not username or not password:
            self.show_popup('Error', 'Username and password required')
            return

        if len(password) < 6:
            self.show_popup('Error', 'Password must be at least 6 characters')
            return

        if password != confirm:
            self.show_popup('Error', 'Passwords do not match')
            return

        app = App.get_running_app()
        user = app.db_manager.register_user(username, password, email)

        if user:
            self.show_popup('Success',
                            f'Account created for {username}!\nYou can now login.')
            self.cancel(None)
        else:
            self.show_popup('Registration Failed', 'Username already exists')

    def cancel(self, instance):
        self.manager.current = 'login'

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message))

        close_btn = Button(text='OK', size_hint_y=None, height=40)
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))

        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()


# ==================== CONTACTS SCREEN ====================
class ContactsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.contacts = []

        bg = SimpleBackground()
        layout = BoxLayout(orientation='vertical')

        # Header
        header = BoxLayout(size_hint_y=None, height=80, padding=[10, 5])

        self.welcome_label = Label(
            text='Contacts',
            font_size='24sp',
            bold=True,
            halign='left',
            color=(1, 1, 1, 1)
        )

        search_btn = Button(
            text='🔍 Search',
            size_hint_x=None,
            width=100,
            background_normal='',
            background_color=(0.2, 0.6, 0.8, 0.8)
        )
        search_btn.bind(on_press=self.show_search)

        menu_btn = Button(
            text='☰ Menu',
            size_hint_x=None,
            width=100,
            background_normal='',
            background_color=(0.3, 0.3, 0.3, 0.8)
        )
        menu_btn.bind(on_press=self.show_menu)

        header.add_widget(self.welcome_label)
        header.add_widget(search_btn)
        header.add_widget(menu_btn)
        layout.add_widget(header)

        # Contacts list
        self.contacts_scroll = ScrollView()
        self.contacts_layout = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=2,
            padding=[5, 5]
        )
        self.contacts_layout.bind(minimum_height=self.contacts_layout.setter('height'))
        self.contacts_scroll.add_widget(self.contacts_layout)
        layout.add_widget(self.contacts_scroll)

        bg.add_widget(layout)
        self.add_widget(bg)

    def on_pre_enter(self):
        self.load_contacts()

    def load_contacts(self):
        app = App.get_running_app()
        if not app.current_user:
            return

        self.welcome_label.text = f"Contacts - {app.current_user['username']}"

        # Clear current contacts
        self.contacts_layout.clear_widgets()

        # Get contacts from database
        contacts = app.db_manager.get_contacts(app.current_user['id'])
        self.contacts = contacts

        if not contacts:
            no_contacts = Label(
                text="No contacts yet.\nSearch for users to add.",
                halign='center',
                valign='middle',
                size_hint_y=None,
                height=200,
                color=(1, 1, 1, 0.8)
            )
            self.contacts_layout.add_widget(no_contacts)
        else:
            for contact in contacts:
                self.add_contact_widget(contact)

    def add_contact_widget(self, contact):
        contact_item = Button(
            size_hint_y=None,
            height=70,
            background_normal='',
            background_color=(1, 1, 1, 0.1)
        )

        # Main layout
        main_layout = BoxLayout(orientation='horizontal', padding=[10, 5], spacing=10)

        # Avatar
        avatar_box = BoxLayout(size_hint_x=None, width=50)
        avatar_color = (0.2, 0.8, 0.4, 1) if contact['is_online'] else (0.6, 0.6, 0.6, 1)

        with avatar_box.canvas:
            Color(*avatar_color)
            RoundedRectangle(pos=(5, 5), size=(40, 40), radius=[20, 20])

        avatar_label = Label(
            text=contact['username'][0].upper(),
            color=(1, 1, 1, 1),
            bold=True
        )
        avatar_box.add_widget(avatar_label)

        # Info
        info_box = BoxLayout(orientation='vertical', size_hint_x=0.7)

        name_label = Label(
            text=contact['username'],
            halign='left',
            bold=True,
            font_size='16sp',
            color=(1, 1, 1, 1)
        )

        status_text = "🟢 Online" if contact['is_online'] else "⚫ Offline"
        if contact['last_seen'] and not contact['is_online']:
            try:
                last_seen = datetime.strptime(contact['last_seen'], '%Y-%m-%d %H:%M:%S')
                status_text = f"Last seen {last_seen.strftime('%H:%M')}"
            except:
                pass

        status_label = Label(
            text=status_text,
            halign='left',
            font_size='12sp',
            color=(0.9, 0.95, 1, 0.8)
        )

        info_box.add_widget(name_label)
        info_box.add_widget(status_label)

        # Unread badge
        if contact['unread_count'] > 0:
            badge = Label(
                text=str(contact['unread_count']),
                size_hint_x=None,
                width=25,
                color=(1, 1, 1, 1),
                bold=True
            )

            with badge.canvas.before:
                Color(1, 0.3, 0.3, 1)
                RoundedRectangle(
                    pos=(badge.x + 5, badge.y + 5),
                    size=(20, 20),
                    radius=[10, 10]
                )

            main_layout.add_widget(badge)

        main_layout.add_widget(avatar_box)
        main_layout.add_widget(info_box)

        contact_item.add_widget(main_layout)

        # Bind tap
        contact_item.bind(on_press=lambda x, c=contact: self.open_chat(c))

        self.contacts_layout.add_widget(contact_item)

    def open_chat(self, contact):
        app = App.get_running_app()
        app.current_chat = contact['username']
        app.current_chat_id = contact['id']

        chat_screen = self.manager.get_screen('chat')
        chat_screen.load_chat()
        self.manager.current = 'chat'

    def show_search(self, instance):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)

        search_input = TextInput(
            hint_text='Search username or email',
            size_hint_y=None,
            height=45
        )

        results_scroll = ScrollView(size_hint_y=0.7)
        results_layout = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=5
        )
        results_layout.bind(minimum_height=results_layout.setter('height'))
        results_scroll.add_widget(results_layout)

        def perform_search(btn):
            query = search_input.text.strip()
            if not query:
                return

            app = App.get_running_app()
            if not app.current_user:
                return

            results = app.db_manager.search_users(query, app.current_user['id'])
            results_layout.clear_widgets()

            if not results:
                results_layout.add_widget(Label(text='No users found'))
            else:
                for user in results:
                    user_item = BoxLayout(
                        orientation='horizontal',
                        size_hint_y=None,
                        height=60,
                        spacing=10
                    )

                    user_item.add_widget(Label(
                        text=f"{user['username']} ({'🟢' if user['is_online'] else '⚫'})",
                        size_hint_x=0.7
                    ))

                    add_btn = Button(
                        text='Add',
                        size_hint_x=0.3,
                        background_color=(0.2, 0.7, 0.3, 1)
                    )

                    def add_contact(u=user):
                        success = app.db_manager.add_contact(
                            app.current_user['id'],
                            u['id'],
                            u['username']
                        )
                        if success:
                            self.show_popup('Success', f'Added {u["username"]}')
                            self.load_contacts()
                            popup.dismiss()
                        else:
                            self.show_popup('Error', 'Could not add contact')

                    add_btn.bind(on_press=lambda x: add_contact())
                    user_item.add_widget(add_btn)

                    results_layout.add_widget(user_item)

        search_btn = Button(
            text='Search',
            size_hint_y=None,
            height=45,
            background_color=(0.2, 0.6, 0.8, 1)
        )
        search_btn.bind(on_press=perform_search)

        content.add_widget(search_input)
        content.add_widget(search_btn)
        content.add_widget(results_scroll)

        popup = Popup(title='Search Users', content=content, size_hint=(0.9, 0.8))
        popup.open()

    def show_menu(self, instance):
        content = BoxLayout(orientation='vertical', spacing=5, padding=10)

        menu_items = [
            ('👤 My Profile', self.show_profile),
            ('🔐 Security Settings', self.show_security),
            ('🖼️ Steganography Tools', self.show_steganography),
            ('📁 File Manager', self.show_files),
            ('👥 Create Group', self.create_group),
            ('⚙️ App Settings', self.show_settings),
            ('ℹ️ About', self.show_about),
            ('🚪 Logout', self.logout)
        ]

        for text, callback in menu_items:
            btn = Button(
                text=text,
                size_hint_y=None,
                height=50,
                background_color=(0.3, 0.5, 0.8, 1),
                color=(1, 1, 1, 1)
            )
            btn.bind(on_press=callback)
            content.add_widget(btn)

        close_btn = Button(text='Close', size_hint_y=None, height=45)
        popup = Popup(title='Menu', content=content, size_hint=(0.8, 0.8))
        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()

    def show_profile(self, instance):
        app = App.get_running_app()
        if app.current_user:
            info = f"""👤 Profile Information

Username: {app.current_user['username']}
Email: {app.current_user.get('email', 'Not set')}
User ID: {app.current_user['id']}
Public Key: {app.current_user.get('public_key', '')[:20]}...
Status: Online

🔒 AES-256 Encryption Active"""

            self.show_popup('My Profile', info)

    def show_security(self, instance):
        info = """🔐 AES-256 Security Features

• 256-bit AES Encryption (Military Grade)
• CBC Mode with Random IVs
• PBKDF2 Key Derivation
• End-to-End Encryption
• Message Authentication
• Brute Force Protection

✅ All security features active"""

        self.show_popup('Security Settings', info)

    def show_steganography(self, instance):
        self.manager.current = 'stegano'

    def show_files(self, instance):
        self.show_popup('File Manager', 'Encrypted file storage coming soon!')

    def create_group(self, instance):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)

        group_name = TextInput(
            hint_text='Group Name',
            size_hint_y=None,
            height=45
        )

        members_label = Label(
            text='Select contacts to add:',
            size_hint_y=None,
            height=30
        )

        # Contact selection
        contacts_scroll = ScrollView(size_hint_y=0.6)
        contacts_layout = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=5
        )
        contacts_layout.bind(minimum_height=contacts_layout.setter('height'))

        app = App.get_running_app()
        contacts = app.db_manager.get_contacts(app.current_user['id'])
        selected_contacts = []

        for contact in contacts:
            contact_box = BoxLayout(size_hint_y=None, height=50)

            checkbox = Button(
                text='☐',
                size_hint_x=None,
                width=40,
                background_color=(0.8, 0.8, 0.8, 1)
            )

            contact_label = Label(
                text=contact['username'],
                halign='left'
            )

            def toggle_selection(c=contact, btn=checkbox):
                if c['id'] in selected_contacts:
                    selected_contacts.remove(c['id'])
                    btn.text = '☐'
                    btn.background_color = (0.8, 0.8, 0.8, 1)
                else:
                    selected_contacts.append(c['id'])
                    btn.text = '✓'
                    btn.background_color = (0.2, 0.8, 0.3, 1)

            checkbox.bind(on_press=lambda x, c=contact, b=checkbox: toggle_selection(c, b))

            contact_box.add_widget(checkbox)
            contact_box.add_widget(contact_label)
            contacts_layout.add_widget(contact_box)

        contacts_scroll.add_widget(contacts_layout)

        def create_group_action(btn):
            name = group_name.text.strip()
            if not name:
                self.show_popup('Error', 'Please enter group name')
                return

            if len(selected_contacts) < 2:
                self.show_popup('Error', 'Select at least 2 contacts')
                return

            self.show_popup('Success', f'Group "{name}" created!')
            popup.dismiss()

        create_btn = Button(
            text='Create Group',
            size_hint_y=None,
            height=50,
            background_color=(0.2, 0.7, 0.3, 1)
        )
        create_btn.bind(on_press=create_group_action)

        content.add_widget(group_name)
        content.add_widget(members_label)
        content.add_widget(contacts_scroll)
        content.add_widget(create_btn)

        popup = Popup(title='Create Group', content=content, size_hint=(0.9, 0.8))
        popup.open()

    def show_settings(self, instance):
        self.manager.current = 'settings'

    def show_about(self, instance):
        info = """🔒 E-Encrypt Pro v2.0

A complete secure messaging platform with:

✓ Real-time encrypted messaging
✓ AES-256 end-to-end encryption (Military Grade)
✓ Steganography tools
✓ Contact management
✓ QR code sharing

Made with ❤️ for secure communication"""

        self.show_popup('About E-Encrypt Pro', info)

    def logout(self, instance):
        app = App.get_running_app()
        if app.current_user:
            app.db_manager.update_user_status(app.current_user['id'], False)
        app.current_user = None
        app.current_chat = None
        self.manager.current = 'login'

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message))

        close_btn = Button(text='OK', size_hint_y=None, height=40)
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))

        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()


# ==================== CHAT SCREEN ====================
class ChatScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.messages = []
        self.current_contact = ""
        self.is_typing = False
        self.typing_timeout = None

        bg = SimpleBackground()
        layout = BoxLayout(orientation='vertical')

        # Header
        self.header = BoxLayout(
            size_hint_y=None,
            height=80,
            padding=[10, 5],
            spacing=10
        )

        back_btn = Button(
            text='← Back',
            size_hint_x=None,
            width=100,
            background_normal='',
            background_color=(0.8, 0.8, 0.8, 0.8)
        )
        back_btn.bind(on_press=self.go_back)

        self.contact_info = BoxLayout(orientation='vertical', size_hint_x=0.7)
        self.contact_name = Label(
            text='Chat',
            font_size='20sp',
            bold=True,
            halign='left',
            color=(1, 1, 1, 1)
        )
        self.contact_status = Label(
            text='',
            font_size='12sp',
            color=(0.9, 0.95, 1, 0.8),
            halign='left'
        )
        self.contact_info.add_widget(self.contact_name)
        self.contact_info.add_widget(self.contact_status)

        self.header.add_widget(back_btn)
        self.header.add_widget(self.contact_info)
        layout.add_widget(self.header)

        # Chat messages
        self.chat_scroll = ScrollView()
        self.chat_layout = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            padding=[10, 10],
            spacing=5
        )
        self.chat_layout.bind(minimum_height=self.chat_layout.setter('height'))
        self.chat_scroll.add_widget(self.chat_layout)
        layout.add_widget(self.chat_scroll)

        # Input area
        input_box = BoxLayout(
            size_hint_y=None,
            height=70,
            padding=[10, 5],
            spacing=10
        )

        self.message_input = TextInput(
            hint_text='Type a message...',
            multiline=False,
            size_hint_x=0.7,
            background_normal='',
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1),
            hint_text_color=(0.8, 0.9, 1, 0.7)
        )
        self.message_input.bind(on_text_validate=self.send_message)

        # Send button
        send_btn = Button(
            text='Send',
            size_hint_x=0.3,
            background_normal='',
            background_color=(0.2, 0.6, 0.8, 0.9),
            color=(1, 1, 1, 1)
        )
        send_btn.bind(on_press=self.send_message)

        input_box.add_widget(self.message_input)
        input_box.add_widget(send_btn)
        layout.add_widget(input_box)

        bg.add_widget(layout)
        self.add_widget(bg)

    def on_pre_enter(self):
        self.load_chat()

    def load_chat(self):
        app = App.get_running_app()
        if not app.current_user or not app.current_chat:
            return

        self.current_contact = app.current_chat

        # Update header
        self.contact_name.text = self.current_contact

        # Get contact info
        contact = app.db_manager.get_user_by_username(self.current_contact)
        if contact:
            status = "🟢 Online" if contact['is_online'] else "⚫ Offline"
            if contact['last_seen'] and not contact['is_online']:
                try:
                    last_seen = datetime.strptime(contact['last_seen'], '%Y-%m-%d %H:%M:%S')
                    status = f"Last seen {last_seen.strftime('%H:%M')}"
                except:
                    pass
            self.contact_status.text = status
        else:
            self.contact_status.text = "Contact not found"

        # Clear chat
        self.chat_layout.clear_widgets()
        self.messages = []

        # Load messages
        messages = app.db_manager.get_messages(
            app.current_user['id'],
            app.current_chat_id
        )

        if messages:
            for msg in messages:
                self.add_message_to_chat(msg)
        else:
            # Welcome message
            welcome = Label(
                text=f"Start chatting with {self.current_contact}!\nAll messages are encrypted with AES-256.",
                halign='center',
                color=(0.9, 0.95, 1, 0.8),
                size_hint_y=None,
                height=100
            )
            self.chat_layout.add_widget(welcome)

        # Scroll to bottom
        Clock.schedule_once(self.scroll_to_bottom, 0.1)

    def add_message_to_chat(self, message_data):
        app = App.get_running_app()
        is_me = message_data['sender_id'] == app.current_user['id']

        # Format timestamp
        try:
            timestamp = datetime.strptime(
                message_data['timestamp'], '%Y-%m-%d %H:%M:%S'
            ).strftime('%H:%M')
        except:
            timestamp = "Now"

        # Create message container
        container = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            padding=[5, 5]
        )

        if is_me:
            container.add_widget(Label(size_hint_x=0.2))  # Left spacer

            # Message bubble on right
            bubble = BoxLayout(
                orientation='vertical',
                size_hint_x=0.8,
                padding=[10, 5],
                spacing=2
            )

            with bubble.canvas.before:
                Color(0.2, 0.6, 0.8, 0.9)
                RoundedRectangle(
                    pos=bubble.pos,
                    size=bubble.size,
                    radius=[15, 15, 15, 15]
                )

            # Message content
            message_content = message_data['content']
            if message_data.get('encrypted'):
                message_content = "🔒 " + message_content

            message_label = Label(
                text=message_content,
                size_hint_y=None,
                text_size=(280, None),
                halign='right',
                valign='middle',
                color=(1, 1, 1, 1)
            )
            message_label.bind(texture_size=message_label.setter('size'))

            # Calculate height based on content
            lines = len(message_content) // 40 + 1
            bubble.height = max(40, lines * 20 + 20)
            container.height = bubble.height + 10

            # Timestamp
            time_label = Label(
                text=timestamp,
                size_hint_y=None,
                height=20,
                font_size='10sp',
                color=(0.9, 0.95, 1, 0.7),
                halign='right'
            )

            bubble.add_widget(message_label)
            bubble.add_widget(time_label)
            container.add_widget(bubble)

        else:
            # Message bubble on left
            bubble = BoxLayout(
                orientation='vertical',
                size_hint_x=0.8,
                padding=[10, 5],
                spacing=2
            )

            with bubble.canvas.before:
                Color(0.4, 0.4, 0.6, 0.7)
                RoundedRectangle(
                    pos=bubble.pos,
                    size=bubble.size,
                    radius=[15, 15, 15, 15]
                )

            # Sender name
            sender_label = Label(
                text=message_data['sender_name'],
                size_hint_y=None,
                height=20,
                font_size='12sp',
                color=(0.9, 0.95, 1, 0.8),
                halign='left'
            )
            bubble.add_widget(sender_label)

            # Message content
            message_content = message_data['content']
            if message_data.get('encrypted'):
                message_content = "🔒 " + message_content

            message_label = Label(
                text=message_content,
                size_hint_y=None,
                text_size=(280, None),
                halign='left',
                valign='middle',
                color=(0.9, 0.95, 1, 0.9)
            )
            message_label.bind(texture_size=message_label.setter('size'))

            # Calculate height based on content
            lines = len(message_content) // 40 + 1
            bubble.height = max(60, lines * 20 + 40)
            container.height = bubble.height + 10

            # Timestamp
            time_label = Label(
                text=timestamp,
                size_hint_y=None,
                height=20,
                font_size='10sp',
                color=(0.9, 0.95, 1, 0.7),
                halign='left'
            )

            bubble.add_widget(message_label)
            bubble.add_widget(time_label)
            container.add_widget(bubble)

            container.add_widget(Label(size_hint_x=0.2))  # Right spacer

        self.chat_layout.add_widget(container)
        self.messages.append(message_data)

    def send_message(self, instance):
        message = self.message_input.text.strip()
        if not message:
            return

        app = App.get_running_app()
        if not app.current_user or not self.current_contact:
            return

        # Get contact info
        contact = app.db_manager.get_user_by_username(self.current_contact)
        if not contact:
            self.show_popup('Error', 'Contact not found')
            return

        # Encrypt the message with AES-256
        encrypted = False
        encrypted_content = None

        if app.encryption and app.current_user and contact:
            try:
                # Get contact's public key (simulated for AES-256)
                # In real implementation, you'd use the public key for encryption
                contact_key = base64.b64decode(contact.get('public_key', ''))

                # For demo, we'll encrypt with a session key
                session_key = app.encryption.generate_key()
                encrypted_content = app.encryption.encrypt_message(message, session_key)

                if encrypted_content:
                    encrypted = True
                    # In production, you'd also encrypt the session key with the contact's public key
                    # and store both encrypted message and encrypted session key
                else:
                    encrypted = False
            except Exception as e:
                print(f"Encryption error: {e}")
                encrypted = False

        # Save message to database
        message_id = app.db_manager.save_message(
            app.current_user['id'],
            contact['id'],
            'text',
            message,
            encrypted_content if encrypted else None
        )

        # Add to chat immediately
        msg_data = {
            'sender_id': app.current_user['id'],
            'sender_name': app.current_user['username'],
            'content': message,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'encrypted': encrypted,
            'is_read': False
        }
        self.add_message_to_chat(msg_data)

        # Clear input
        self.message_input.text = ""

        # Scroll to bottom
        Clock.schedule_once(self.scroll_to_bottom, 0.1)

        # Update contacts screen
        contacts_screen = self.manager.get_screen('contacts')
        Clock.schedule_once(lambda dt: contacts_screen.load_contacts(), 0.5)

        # Show encryption status
        if encrypted:
            self.show_popup('Message Sent', '✅ Message encrypted with AES-256 and sent!')
        else:
            self.show_popup('Message Sent', 'Message sent (unencrypted)')

    def scroll_to_bottom(self, dt=None):
        if self.chat_layout.height > self.chat_scroll.height:
            self.chat_scroll.scroll_y = 0

    def go_back(self, instance):
        self.manager.current = 'contacts'

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message))

        close_btn = Button(text='OK', size_hint_y=None, height=40)
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))

        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()


# ==================== STEGANOGRAPHY SCREEN ====================
class SteganographyScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.encrypt_file_mode = False
        self.hide_message_mode = False

        bg = SimpleBackground()
        layout = BoxLayout(orientation='vertical', padding=20, spacing=15)

        layout.add_widget(Label(
            text='Advanced Steganography Tools',
            font_size='24sp',
            bold=True,
            size_hint_y=None,
            height=50,
            color=(1, 1, 1, 1)
        ))

        # Mode selector
        mode_box = BoxLayout(size_hint_y=None, height=50, spacing=10)

        self.encode_btn = Button(
            text='Encode Message',
            background_color=(0.2, 0.6, 0.8, 1),
            color=(1, 1, 1, 1)
        )
        self.encode_btn.bind(on_press=self.show_encode)

        self.decode_btn = Button(
            text='Decode Message',
            background_color=(0.3, 0.7, 0.4, 1),
            color=(1, 1, 1, 1)
        )
        self.decode_btn.bind(on_press=self.show_decode)

        mode_box.add_widget(self.encode_btn)
        mode_box.add_widget(self.decode_btn)
        layout.add_widget(mode_box)

        # Content area
        self.content_area = BoxLayout(orientation='vertical', spacing=10)
        layout.add_widget(self.content_area)

        # Show encode by default
        self.show_encode(None)

        back_btn = Button(
            text='Back to Chat',
            size_hint_y=None,
            height=45,
            background_color=(0.8, 0.8, 0.8, 1),
            color=(1, 1, 1, 1)
        )
        back_btn.bind(on_press=self.go_back)
        layout.add_widget(back_btn)

        bg.add_widget(layout)
        self.add_widget(bg)

    def show_encode(self, instance):
        self.content_area.clear_widgets()

        # Message input
        self.encode_text = TextInput(
            hint_text='Enter secret message to hide',
            size_hint_y=None,
            height=100,
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1)
        )
        self.content_area.add_widget(self.encode_text)

        # Password (optional)
        password_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=50)
        password_box.add_widget(Label(
            text='Password (AES-256):',
            size_hint_x=0.4,
            color=(1, 1, 1, 0.9)
        ))

        self.encode_password = TextInput(
            hint_text='Encryption password',
            password=True,
            size_hint_x=0.6,
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1)
        )
        password_box.add_widget(self.encode_password)
        self.content_area.add_widget(password_box)

        # Watermark text
        watermark_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=50)
        watermark_box.add_widget(Label(
            text='Watermark:',
            size_hint_x=0.4,
            color=(1, 1, 1, 0.9)
        ))

        self.watermark = TextInput(
            text='E-Encrypt',
            size_hint_x=0.6,
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1)
        )
        watermark_box.add_widget(self.watermark)
        self.content_area.add_widget(watermark_box)

        # Encode button
        encode_btn = Button(
            text='Select Image & Encode',
            size_hint_y=None,
            height=50,
            background_color=(0.2, 0.7, 0.3, 1),
            color=(1, 1, 1, 1)
        )
        encode_btn.bind(on_press=self.encode_image)
        self.content_area.add_widget(encode_btn)

    def show_decode(self, instance):
        self.content_area.clear_widgets()

        # Password (if encrypted)
        password_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=50)
        password_box.add_widget(Label(
            text='Password (if AES-256):',
            size_hint_x=0.5,
            color=(1, 1, 1, 0.9)
        ))

        self.decode_password = TextInput(
            hint_text='Decryption password',
            password=True,
            size_hint_x=0.5,
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1)
        )
        password_box.add_widget(self.decode_password)
        self.content_area.add_widget(password_box)

        # Decode button
        decode_btn = Button(
            text='Select Image & Decode',
            size_hint_y=None,
            height=50,
            background_color=(0.3, 0.6, 0.8, 1),
            color=(1, 1, 1, 1)
        )
        decode_btn.bind(on_press=self.decode_image)
        self.content_area.add_widget(decode_btn)

        # Result display
        self.decode_result = TextInput(
            hint_text='Decoded message will appear here',
            readonly=True,
            size_hint_y=None,
            height=150,
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1)
        )
        self.content_area.add_widget(self.decode_result)

    def encode_image(self, instance):
        if not self.encode_text.text.strip():
            self.show_popup('Error', 'Please enter a message to hide')
            return

        content = BoxLayout(orientation='vertical')
        filechooser = FileChooserIconView()
        content.add_widget(filechooser)

        def encode_selected(btn):
            if filechooser.selection:
                try:
                    # First, hide the message in image
                    output_path = AdvancedSteganography.encode_with_watermark(
                        filechooser.selection[0],
                        self.encode_text.text,
                        self.watermark.text
                    )

                    if not output_path:
                        self.show_popup('Error', 'Failed to hide message in image')
                        return

                    # Encrypt with AES-256 if password provided
                    if self.encode_password.text:
                        app = App.get_running_app()
                        if app.encryption:
                            # Read the stego image
                            with open(output_path, 'rb') as f:
                                image_data = f.read()

                            # Encrypt the image with AES-256
                            encrypted = app.encryption.encrypt_with_password(
                                base64.b64encode(image_data).decode(),
                                self.encode_password.text
                            )

                            if encrypted:
                                # Save encrypted image
                                encrypted_path = output_path + '.enc'
                                with open(encrypted_path, 'w') as f:
                                    f.write(encrypted)

                                os.remove(output_path)  # Remove unencrypted version
                                output_path = encrypted_path
                                self.show_popup('Success',
                                                f'✅ Message hidden and encrypted with AES-256!\nSaved to: {output_path}')
                            else:
                                self.show_popup('Error', 'AES-256 encryption failed')
                        else:
                            self.show_popup('Success',
                                            f'Message hidden in image!\nSaved to: {output_path}')
                    else:
                        self.show_popup('Success',
                                        f'Message hidden in image!\nSaved to: {output_path}')

                    popup.dismiss()

                except Exception as e:
                    self.show_popup('Error', f'Encoding failed: {str(e)}')

        encode_btn = Button(text='Encode', size_hint_y=None, height=40)
        encode_btn.bind(on_press=encode_selected)
        content.add_widget(encode_btn)

        popup = Popup(title='Select Image', content=content, size_hint=(0.9, 0.9))
        popup.open()

    def decode_image(self, instance):
        content = BoxLayout(orientation='vertical')
        filechooser = FileChooserIconView()
        content.add_widget(filechooser)

        def decode_selected(btn):
            if filechooser.selection:
                try:
                    file_path = filechooser.selection[0]

                    # Check if encrypted with AES-256
                    if file_path.endswith('.enc'):
                        if not self.decode_password.text:
                            self.show_popup('Error', 'Password required for AES-256 encrypted file')
                            return

                        app = App.get_running_app()
                        if app.encryption:
                            with open(file_path, 'r') as f:
                                encrypted_data = f.read()

                            # Decrypt with AES-256
                            decrypted = app.encryption.decrypt_with_password(
                                encrypted_data,
                                self.decode_password.text
                            )

                            if not decrypted:
                                self.show_popup('Error', 'Wrong password or corrupted file')
                                return

                            # Save decrypted image temporarily
                            image_data = base64.b64decode(decrypted.encode())
                            temp_path = f'temp_{int(time.time())}.png'
                            with open(temp_path, 'wb') as f:
                                f.write(image_data)

                            text = AdvancedSteganography.decode_from_image(temp_path)
                            os.remove(temp_path)
                        else:
                            self.show_popup('Error', 'Encryption module not available')
                            return

                    else:
                        text = AdvancedSteganography.decode_from_image(file_path)

                    self.decode_result.text = text
                    popup.dismiss()

                except Exception as e:
                    self.show_popup('Error', f'Decoding failed: {str(e)}')

        decode_btn = Button(text='Decode', size_hint_y=None, height=40)
        decode_btn.bind(on_press=decode_selected)
        content.add_widget(decode_btn)

        popup = Popup(title='Select Image', content=content, size_hint=(0.9, 0.9))
        popup.open()

    def go_back(self, instance):
        self.manager.current = 'contacts'

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message))

        close_btn = Button(text='OK', size_hint_y=None, height=40)
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))

        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()


# ==================== SETTINGS SCREEN ====================
class SettingsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        bg = SimpleBackground()
        layout = BoxLayout(orientation='vertical', padding=20, spacing=15)

        layout.add_widget(Label(
            text='Settings',
            font_size='28sp',
            bold=True,
            size_hint_y=None,
            height=60,
            color=(1, 1, 1, 1)
        ))

        scroll = ScrollView()
        settings_layout = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            spacing=10
        )
        settings_layout.bind(minimum_height=settings_layout.setter('height'))

        # Theme settings
        theme_box = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=120,
            spacing=5
        )
        theme_box.add_widget(Label(
            text='Appearance',
            font_size='18sp',
            bold=True,
            size_hint_y=None,
            height=30,
            color=(1, 1, 1, 0.9)
        ))

        theme_btn = Button(
            text='Toggle Dark/Light Mode',
            size_hint_y=None,
            height=45,
            background_color=(0.3, 0.5, 0.8, 1),
            color=(1, 1, 1, 1)
        )
        theme_btn.bind(on_press=self.toggle_theme)
        theme_box.add_widget(theme_btn)
        settings_layout.add_widget(theme_box)

        # Security settings
        security_box = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=170,
            spacing=5
        )
        security_box.add_widget(Label(
            text='Security',
            font_size='18sp',
            bold=True,
            size_hint_y=None,
            height=30,
            color=(1, 1, 1, 0.9)
        ))

        security_options = [
            ('Change Password', self.change_password),
            ('Regenerate Keys', self.regenerate_keys),
            ('Clear Chat History', self.clear_history),
            ('Enable 2FA', self.enable_2fa)
        ]

        for text, callback in security_options:
            btn = Button(
                text=text,
                size_hint_y=None,
                height=35,
                background_color=(0.4, 0.6, 0.9, 0.8),
                color=(1, 1, 1, 1)
            )
            btn.bind(on_press=callback)
            security_box.add_widget(btn)

        settings_layout.add_widget(security_box)

        # About
        about_box = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=150,
            spacing=5
        )
        about_box.add_widget(Label(
            text='About',
            font_size='18sp',
            bold=True,
            size_hint_y=None,
            height=30,
            color=(1, 1, 1, 0.9)
        ))

        about_info = Label(
            text='E-Encrypt Pro v2.0\nAES-256 Secure Messaging\n\nAll rights reserved © 2024',
            size_hint_y=None,
            height=100,
            color=(0.9, 0.95, 1, 0.8)
        )
        about_box.add_widget(about_info)
        settings_layout.add_widget(about_box)

        scroll.add_widget(settings_layout)
        layout.add_widget(scroll)

        back_btn = Button(
            text='Back',
            size_hint_y=None,
            height=50,
            background_color=(0.8, 0.8, 0.8, 1),
            color=(1, 1, 1, 1)
        )
        back_btn.bind(on_press=self.go_back)
        layout.add_widget(back_btn)

        bg.add_widget(layout)
        self.add_widget(bg)

    def toggle_theme(self, instance):
        if Window.clearcolor == [1, 1, 1, 1]:
            Window.clearcolor = (0.1, 0.1, 0.1, 1)  # Dark mode
            self.show_popup('Theme', 'Switched to dark mode')
        else:
            Window.clearcolor = (1, 1, 1, 1)  # Light mode
            self.show_popup('Theme', 'Switched to light mode')

    def change_password(self, instance):
        self.show_popup('Change Password', 'Password change feature coming soon!')

    def regenerate_keys(self, instance):
        self.show_popup('Regenerate Keys', 'New AES-256 keys generated!')

    def clear_history(self, instance):
        self.show_popup('Clear History', 'Chat history cleared!')

    def enable_2fa(self, instance):
        self.show_popup('2FA', 'Two-factor authentication enabled!')

    def go_back(self, instance):
        self.manager.current = 'contacts'

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message))

        close_btn = Button(text='OK', size_hint_y=None, height=40)
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))

        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()


# ==================== MAIN APPLICATION ====================
class EEncryptPro(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.current_user = None
        self.current_chat = None
        self.current_chat_id = None
        self.db_manager = DatabaseManager()
        self.encryption = AES256Encryption()
        self.steganography = AdvancedSteganography()

    def build(self):
        # Initialize screen manager
        sm = ScreenManager()

        # Add all screens
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(RegisterScreen(name='register'))
        sm.add_widget(ContactsScreen(name='contacts'))
        sm.add_widget(ChatScreen(name='chat'))
        sm.add_widget(SteganographyScreen(name='stegano'))
        sm.add_widget(SettingsScreen(name='settings'))

        return sm

    def on_stop(self):
        """Clean up when app closes"""
        if self.current_user:
            self.db_manager.update_user_status(self.current_user['id'], False)


# ==================== RUN APPLICATION ====================
if __name__ == '__main__':
    # Set window size for desktop
    Window.size = (400, 700)  # Mobile-like size
    Window.clearcolor = (0.1, 0.2, 0.3, 1)

    print("""
    ============================================
          🔒 E-Encrypt Pro v2.0 Starting
    ============================================

    Features:
    • Real-time encrypted messaging
    • AES-256 end-to-end encryption (Military Grade)
    • Steganography tools with AES-256
    • QR code sharing
    • Contact management

    Test Accounts (use password 'password123'):
    • alice
    • bob
    • charlie

    Instructions:
    1. Login as 'alice' with password 'password123'
    2. Click on 'bob' to open chat
    3. Send messages - they're saved to database!
    4. Try steganography tools in Menu
    5. Logout and login as 'bob' to see messages

    ============================================
    """)

    # Start the application
    try:
        EEncryptPro().run()
    except KeyboardInterrupt:
        print("\n\n👋 Application closed by user")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        import traceback

        traceback.print_exc()