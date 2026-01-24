"""
Reset the database to fix schema issues
Run: python reset_database.py
"""

import os
import sqlite3

print("🔄 Resetting database...")

# Delete the database file if it exists
if os.path.exists("eencrypt.db"):
    os.remove("eencrypt.db")
    print("✅ Deleted old database")

# Create a new database with correct schema
conn = sqlite3.connect('eencrypt.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    avatar_color TEXT DEFAULT '#25D366',
    status TEXT DEFAULT 'Secure & Encrypted 🔐',
    is_online BOOLEAN DEFAULT FALSE,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

# Create messages table
cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    chat_id TEXT NOT NULL,
    content TEXT NOT NULL,
    encrypted BOOLEAN DEFAULT FALSE,
    encryption_key TEXT,
    message_type TEXT DEFAULT 'text',
    read BOOLEAN DEFAULT FALSE,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (receiver_id) REFERENCES users (id)
)
''')

# Create indexes
cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id)')

# Insert test users
import hashlib
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

test_users = [
    ('alice', hash_password('password123'), 'alice@eencrypt.com', None, '#25D366'),
    ('bob', hash_password('password123'), 'bob@eencrypt.com', None, '#FF6B6B'),
    ('charlie', hash_password('password123'), 'charlie@eencrypt.com', None, '#4ECDC4'),
    ('david', hash_password('password123'), 'david@eencrypt.com', None, '#FFD166'),
    ('emma', hash_password('password123'), 'emma@eencrypt.com', None, '#9D4EDD'),
]

cursor.executemany('''
INSERT INTO users (username, password_hash, email, phone, avatar_color, is_online)
VALUES (?, ?, ?, ?, ?, TRUE)
''', test_users)

conn.commit()
conn.close()

print(f"✅ Created new database with {len(test_users)} test users")
print("👥 Test users: alice, bob, charlie, david, emma")
print("🔑 Password for all: password123")
print("\nNow start the backend:")
print("python backend_api.py")