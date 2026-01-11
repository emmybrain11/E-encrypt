import sqlite3
import hashlib
from datetime import datetime


class DatabaseManager:
    def __init__(self, db_path="eencrypt.db"):
        self.db_path = db_path
        self.conn = None

    def initialize(self):
        """Initialize database with basic tables"""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password_hash TEXT,
                duress_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                recipient_id INTEGER,
                message TEXT,
                encrypted INTEGER DEFAULT 1,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Contacts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT,
                identifier TEXT,
                is_emergency INTEGER DEFAULT 0
            )
        ''')

        # Vault items
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT,
                real_content TEXT,
                fake_content TEXT,
                category TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        self.conn.commit()
        return True

    def user_exists(self):
        """Check if any users exist"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        return count > 0

    def create_user(self, password, duress_password=None):
        """Create new user"""
        try:
            cursor = self.conn.cursor()

            # Hash passwords
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            duress_hash = hashlib.sha256(duress_password.encode()).hexdigest() if duress_password else None

            # Create username
            username = f"user_{int(datetime.now().timestamp()) % 10000}"

            cursor.execute('''
                INSERT INTO users (username, password_hash, duress_hash)
                VALUES (?, ?, ?)
            ''', (username, password_hash, duress_hash))

            user_id = cursor.lastrowid
            self.conn.commit()

            # Add some demo contacts
            self.add_demo_contacts(user_id)

            return user_id

        except Exception as e:
            print(f"Error creating user: {e}")
            return None

    def add_demo_contacts(self, user_id):
        """Add demo contacts for new user"""
        demo_contacts = [
            ("Security Team", "sec_team", 1),
            ("Emergency Contact", "emergency", 1),
            ("Friend 1", "friend1", 0),
            ("Friend 2", "friend2", 0)
        ]

        cursor = self.conn.cursor()
        for name, identifier, is_emergency in demo_contacts:
            cursor.execute('''
                INSERT INTO contacts (user_id, name, identifier, is_emergency)
                VALUES (?, ?, ?, ?)
            ''', (user_id, name, identifier, is_emergency))

        self.conn.commit()

    def authenticate(self, password, use_duress=False):
        """Authenticate user"""
        try:
            cursor = self.conn.cursor()
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            if use_duress:
                query = "SELECT id, username FROM users WHERE duress_hash = ?"
            else:
                query = "SELECT id, username FROM users WHERE password_hash = ?"

            cursor.execute(query, (password_hash,))
            result = cursor.fetchone()

            if result:
                return {"id": result[0], "username": result[1]}
            return None

        except Exception as e:
            print(f"Authentication error: {e}")
            return None

    def save_message(self, sender_id, recipient_id, message, encrypted=True):
        """Save message to database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO messages (sender_id, recipient_id, message, encrypted)
                VALUES (?, ?, ?, ?)
            ''', (sender_id, recipient_id, message, 1 if encrypted else 0))

            self.conn.commit()
            return cursor.lastrowid

        except Exception as e:
            print(f"Error saving message: {e}")
            return None

    def get_contacts(self, user_id):
        """Get user's contacts"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT id, name, identifier, is_emergency 
                FROM contacts 
                WHERE user_id = ?
            ''', (user_id,))

            contacts = []
            for row in cursor.fetchall():
                contacts.append({
                    'id': row[0],
                    'name': row[1],
                    'identifier': row[2],
                    'is_emergency': bool(row[3])
                })

            return contacts

        except Exception as e:
            print(f"Error getting contacts: {e}")
            return []

    def get_messages(self, user_id, contact_id):
        """Get messages between user and contact"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT sender_id, message, timestamp, encrypted
                FROM messages
                WHERE (sender_id = ? AND recipient_id = ?)
                   OR (sender_id = ? AND recipient_id = ?)
                ORDER BY timestamp
            ''', (user_id, contact_id, contact_id, user_id))

            messages = []
            for row in cursor.fetchall():
                messages.append({
                    'sender_id': row[0],
                    'message': row[1],
                    'timestamp': row[2],
                    'encrypted': bool(row[3])
                })

            return messages

        except Exception as e:
            print(f"Error getting messages: {e}")
            return []
