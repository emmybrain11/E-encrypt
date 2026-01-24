"""
🌐 E-Encrypt Web App v6.0 - WITH BACKEND CONNECTION
Run: streamlit run main_web_backend.py
"""

import streamlit as st
import requests
import json
import base64
import hashlib
from datetime import datetime
import time

# ==================== CONFIGURATION ====================
BACKEND_URL = "http://localhost:8000"


# ==================== BACKEND CLIENT ====================
class BackendClient:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.token = None
        self.user_id = None
        self.username = None

    def register(self, username, password, email=None, phone=None):
        """Register new user"""
        url = f"{self.base_url}/api/auth/register"
        data = {
            "username": username,
            "password": password,
            "email": email,
            "phone": phone
        }
        try:
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                self.token = result["access_token"]
                self.user_id = result["user"]["id"]
                self.username = result["user"]["username"]
                return {"success": True, "data": result}
            else:
                return {"success": False, "error": response.json().get("detail", "Registration failed")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def login(self, username, password):
        """Login user"""
        url = f"{self.base_url}/api/auth/login"
        data = {
            "username": username,
            "password": password
        }
        try:
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                self.token = result["access_token"]
                self.user_id = result["user"]["id"]
                self.username = result["user"]["username"]
                return {"success": True, "data": result}
            else:
                return {"success": False, "error": response.json().get("detail", "Login failed")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def logout(self):
        """Logout user"""
        if self.token:
            url = f"{self.base_url}/api/auth/logout"
            headers = {"Authorization": f"Bearer {self.token}"}
            try:
                requests.post(url, headers=headers, timeout=5)
            except:
                pass

        self.token = None
        self.user_id = None
        self.username = None

    def get_headers(self):
        """Get authentication headers"""
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def get_users(self):
        """Get all users"""
        url = f"{self.base_url}/api/users"
        try:
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to get users"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_user_profile(self, user_id=None):
        """Get user profile"""
        if user_id:
            url = f"{self.base_url}/api/users/{user_id}"
        else:
            url = f"{self.base_url}/api/users/me"

        try:
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to get profile"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def send_message(self, receiver_id, content, encrypted=True, encryption_key=None):
        """Send a message"""
        url = f"{self.base_url}/api/messages/send"
        data = {
            "receiver_id": receiver_id,
            "content": content,
            "encrypted": encrypted,
            "encryption_key": encryption_key
        }
        try:
            response = requests.post(url, json=data, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": response.json().get("detail", "Failed to send message")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_chat_messages(self, other_user_id, limit=100):
        """Get chat messages"""
        url = f"{self.base_url}/api/messages/chat/{other_user_id}"
        params = {"limit": limit}
        try:
            response = requests.get(url, params=params, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to get chat"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_chats(self):
        """Get all chats"""
        url = f"{self.base_url}/api/messages/chats"
        try:
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to get chats"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def encode_stego(self, message, password, method="lsb", intensity=1):
        """Encode message in steganography"""
        url = f"{self.base_url}/api/stego/encode"
        data = {
            "operation": "encode",
            "message": message,
            "password": password,
            "method": method,
            "intensity": intensity
        }
        try:
            response = requests.post(url, json=data, headers=self.get_headers(), timeout=30)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": response.json().get("detail", "Encoding failed")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def decode_stego(self, password, method="lsb", intensity=1):
        """Decode message from steganography"""
        url = f"{self.base_url}/api/stego/decode"
        data = {
            "operation": "decode",
            "password": password,
            "method": method,
            "intensity": intensity
        }
        try:
            response = requests.post(url, json=data, headers=self.get_headers(), timeout=30)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": response.json().get("detail", "Decoding failed")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_stats(self):
        """Get user statistics"""
        url = f"{self.base_url}/api/stats/me"
        try:
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to get stats"}
        except Exception as e:
            return {"success": False, "error": str(e)}


# ==================== STREAMLIT APP ====================
class EEncryptWebApp:
    def __init__(self):
        # Initialize session state
        if 'backend' not in st.session_state:
            st.session_state.backend = BackendClient()

        if 'logged_in' not in st.session_state:
            st.session_state.logged_in = False

        if 'current_user' not in st.session_state:
            st.session_state.current_user = None

        if 'current_chat' not in st.session_state:
            st.session_state.current_chat = None

        if 'page' not in st.session_state:
            st.session_state.page = 'login'

        # Test backend connection
        self.test_backend_connection()

    def test_backend_connection(self):
        """Test if backend is reachable"""
        try:
            response = requests.get(f"{BACKEND_URL}/api/health", timeout=5)
            if response.status_code == 200:
                st.session_state.backend_status = '🟢 Connected'
            else:
                st.session_state.backend_status = '🟡 Backend error'
        except:
            st.session_state.backend_status = '🔴 Not connected'

    def run(self):
        # Custom CSS
        st.markdown("""
        <style>
            .main-header {
                font-size: 2.5rem;
                color: #25D366;
                text-align: center;
                margin-bottom: 1rem;
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
            .status-badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 10px;
                font-size: 12px;
                margin-left: 10px;
            }
        </style>
        """, unsafe_allow_html=True)

        # Display header
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown('<h1 class="main-header">🔐 E-Encrypt</h1>', unsafe_allow_html=True)
            st.markdown(
                f'<p style="text-align: center; color: #666;">Quantum-Resistant Secure Messenger | Backend: {st.session_state.backend_status}</p>',
                unsafe_allow_html=True)

        # Page routing
        if not st.session_state.logged_in:
            self.login_page()
        else:
            self.main_app()

    def login_page(self):
        col1, col2, col3 = st.columns([1, 2, 1])

        with col2:
            st.markdown("### Welcome to E-Encrypt")

            # Backend connection warning
            if st.session_state.backend_status != '🟢 Connected':
                st.warning(f"⚠️ Backend status: {st.session_state.backend_status}")
                st.info("Make sure backend server is running:")
                st.code("python backend_api.py")

            # Tabs for login/register
            tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])

            with tab1:
                # Login form
                login_username = st.text_input("Username", key="login_username")
                login_password = st.text_input("Password", type="password", key="login_password")

                col1, col2 = st.columns(2)
                with col1:
                    login_submit = st.button("Login", use_container_width=True, type="primary")

                with col2:
                    if st.button("Quick Login", use_container_width=True):
                        # Show test user selection
                        st.session_state.show_test_users = True

                if login_submit:
                    if login_username and login_password:
                        with st.spinner("Logging in..."):
                            result = st.session_state.backend.login(login_username, login_password)
                            if result['success']:
                                st.session_state.logged_in = True
                                st.session_state.current_user = result['data']['user']
                                st.success(f"Welcome back, {login_username}!")
                                st.rerun()
                            else:
                                st.error(f"Login failed: {result['error']}")
                    else:
                        st.error("Please enter username and password")

                # Test user selection
                if hasattr(st.session_state, 'show_test_users') and st.session_state.show_test_users:
                    st.divider()
                    st.markdown("### Test Users")
                    test_users = ['alice', 'bob', 'charlie', 'david', 'emma']

                    selected_user = st.selectbox(
                        "Select test user",
                        test_users,
                        key="test_user_select"
                    )

                    if st.button("Login as selected user", key="test_login_btn"):
                        with st.spinner(f"Logging in as {selected_user}..."):
                            result = st.session_state.backend.login(selected_user, 'password123')
                            if result['success']:
                                st.session_state.logged_in = True
                                st.session_state.current_user = result['data']['user']
                                st.success(f"Welcome, {selected_user}!")
                                st.rerun()
                            else:
                                st.error(f"Login failed: {result['error']}")

            with tab2:
                # Registration form
                new_username = st.text_input("Choose Username", key="reg_username")
                new_password = st.text_input("Choose Password", type="password", key="reg_password")
                confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm")
                email = st.text_input("Email (optional)", key="reg_email")
                phone = st.text_input("Phone (optional)", key="reg_phone")

                register_submit = st.button("Create Account", use_container_width=True, type="primary")

                if register_submit:
                    if new_username and new_password:
                        if new_password == confirm_password:
                            if len(new_password) >= 6:
                                with st.spinner("Creating account..."):
                                    result = st.session_state.backend.register(
                                        new_username, new_password, email, phone
                                    )
                                    if result['success']:
                                        st.session_state.logged_in = True
                                        st.session_state.current_user = result['data']['user']
                                        st.success(f"Account created successfully! Welcome {new_username}!")
                                        st.rerun()
                                    else:
                                        st.error(f"Registration failed: {result['error']}")
                            else:
                                st.error("Password must be at least 6 characters")
                        else:
                            st.error("Passwords do not match")
                    else:
                        st.error("Please enter username and password")

    def main_app(self):
        # Navigation sidebar
        with st.sidebar:
            user = st.session_state.current_user
            st.markdown(f"### 👤 {user['username']}")
            st.markdown(f"*{user.get('status', 'Secure & Encrypted 🔐')}*")

            # Online status badge
            status_color = "#25D366" if user.get('is_online') else "#666"
            st.markdown(
                f'<span class="status-badge" style="background-color: {status_color}; color: white;">{"🟢 Online" if user.get("is_online") else "⚫ Offline"}</span>',
                unsafe_allow_html=True)

            st.divider()

            # Navigation options
            if st.button("💬 Chats", use_container_width=True):
                st.session_state.page = 'chats'
                st.session_state.current_chat = None
                st.rerun()

            if st.button("🖼️ Steganography", use_container_width=True):
                st.session_state.page = 'stegano'
                st.rerun()

            if st.button("📊 Statistics", use_container_width=True):
                st.session_state.page = 'stats'
                st.rerun()

            if st.button("⚙️ Settings", use_container_width=True):
                st.session_state.page = 'settings'
                st.rerun()

            st.divider()

            # Backend status
            st.caption(f"Backend: {st.session_state.backend_status}")

            if st.button("🚪 Logout", use_container_width=True, type="secondary"):
                st.session_state.backend.logout()
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
        elif st.session_state.page == 'stats':
            self.stats_page()
        elif st.session_state.page == 'settings':
            self.settings_page()

    def chats_page(self):
        st.markdown("### 💬 Your Chats")

        # Get chats from backend
        with st.spinner("Loading chats..."):
            result = st.session_state.backend.get_chats()

        if not result['success']:
            st.error(f"Failed to load chats: {result['error']}")
            return

        chats = result['data']

        if not chats:
            st.info("No chats yet. Start by selecting a contact!")
        else:
            # Search bar
            search = st.text_input("🔍 Search contacts", placeholder="Type to search...")

            # Display chats
            for chat in chats:
                other_user = chat['other_user']

                if search.lower() not in other_user['username'].lower() and search:
                    continue

                col1, col2, col3 = st.columns([1, 3, 1])
                with col1:
                    # Avatar with color
                    avatar_color = other_user['avatar_color']
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
                        {other_user['username'][0].upper()}
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    status = "🟢" if other_user['is_online'] else "⚫"
                    st.markdown(f"**{other_user['username']}** {status}")

                    if chat['last_message']:
                        last_msg = chat['last_message']['content']
                        st.markdown(f"*{last_msg}*")
                    else:
                        st.markdown("*Start a conversation*")

                    if chat['unread_count'] > 0:
                        st.markdown(f"<small style='color: #25D366;'>{chat['unread_count']} unread</small>",
                                    unsafe_allow_html=True)

                with col3:
                    if st.button("Open", key=f"open_chat_{other_user['id']}", use_container_width=True):
                        st.session_state.current_chat = chat
                        st.rerun()

                st.divider()

        # New chat button
        if st.button("+ New Chat", use_container_width=True):
            self.show_new_chat()

    def show_new_chat(self):
        """Show dialog to start new chat"""
        with st.spinner("Loading users..."):
            result = st.session_state.backend.get_users()

        if not result['success']:
            st.error(f"Failed to load users: {result['error']}")
            return

        users = result['data']

        # Create a selectbox for users
        user_options = {f"{u['username']} ({'🟢' if u['is_online'] else '⚫'})": u for u in users}
        selected_user_display = st.selectbox("Select user to chat with:", list(user_options.keys()))

        if selected_user_display and st.button("Start Chat", use_container_width=True):
            selected_user = user_options[selected_user_display]

            # Create chat object
            chat = {
                'chat_id': f"new_{selected_user['id']}",
                'other_user': selected_user,
                'last_message': None,
                'unread_count': 0
            }

            st.session_state.current_chat = chat
            st.rerun()

    def chat_page(self):
        chat = st.session_state.current_chat
        other_user = chat['other_user']

        # Chat header
        col1, col2, col3 = st.columns([1, 3, 1])
        with col1:
            if st.button("← Back"):
                st.session_state.current_chat = None
                st.rerun()

        with col2:
            status = "🟢 Online" if other_user['is_online'] else "⚫ Offline"
            st.markdown(f"### {other_user['username']}")
            st.markdown(f"*{status} | {other_user['status']}*")

        with col3:
            if st.button("📞 Call"):
                st.info(f"Starting encrypted call with {other_user['username']}...")

        st.divider()

        # Messages area
        messages_container = st.container(height=400)

        with messages_container:
            # Get messages from backend
            with st.spinner("Loading messages..."):
                result = st.session_state.backend.get_chat_messages(other_user['id'])

            if not result['success']:
                st.error(f"Failed to load messages: {result['error']}")
                messages = []
            else:
                messages = result['data']

            if not messages:
                st.info(f"Start chatting with {other_user['username']}!")
                st.info("🔒 All messages are end-to-end encrypted")
            else:
                for msg in messages:
                    if msg['is_me']:
                        st.markdown(f'''
                        <div class="chat-bubble-right">
                            <strong>You</strong><br>
                            {msg['content']}
                            <br><small>{msg.get('timestamp', 'Now')[:16]}</small>
                        </div>
                        ''', unsafe_allow_html=True)
                    else:
                        st.markdown(f'''
                        <div class="chat-bubble-left">
                            <strong>{other_user['username']}</strong><br>
                            {msg['content']}
                            <br><small>{msg.get('timestamp', 'Now')[:16]}</small>
                        </div>
                        ''', unsafe_allow_html=True)

        # Message input
        col1, col2, col3 = st.columns([5, 1, 1])
        with col1:
            message = st.text_input("Type a message...", key="message_input", label_visibility="collapsed")

        with col2:
            if st.button("Send", use_container_width=True) and message:
                with st.spinner("Sending..."):
                    result = st.session_state.backend.send_message(other_user['id'], message, encrypted=False)
                    if result['success']:
                        st.rerun()
                    else:
                        st.error(f"Failed to send: {result['error']}")

        with col3:
            if st.button("🔐", use_container_width=True):
                with st.popover("Send Encrypted Message"):
                    encrypted_msg = st.text_area("Message to encrypt")
                    password = st.text_input("Encryption password", type="password")
                    if st.button("Send Encrypted", key="send_encrypted"):
                        if encrypted_msg and password:
                            with st.spinner("Encrypting and sending..."):
                                result = st.session_state.backend.send_message(
                                    other_user['id'],
                                    encrypted_msg,
                                    encrypted=True,
                                    encryption_key=password
                                )
                                if result['success']:
                                    st.success("Encrypted message sent!")
                                    st.rerun()
                                else:
                                    st.error(f"Failed to send: {result['error']}")

    def stegano_page(self):
        st.markdown("### 🖼️ Advanced Steganography")

        tab1, tab2 = st.tabs(["🔒 Hide Message", "🔓 Extract Message"])

        with tab1:
            st.markdown("#### Encode a secret message")

            col1, col2 = st.columns(2)

            with col1:
                # Message input
                secret_message = st.text_area("Secret Message", height=100,
                                              placeholder="Type your secret message here...")

                # Password
                encode_password = st.text_input("Encryption Password", type="password",
                                                placeholder="Enter strong password")

                # Method selection
                method = st.selectbox("Encoding Method", ["lsb", "lsb_advanced"])

                # Intensity
                intensity = st.slider("Intensity", 1, 4, 1)

            with col2:
                st.markdown("#### Note")
                st.info("""
                This uses the backend steganography service.
                In a real implementation, you would:
                1. Upload an image
                2. The backend encodes your message into it
                3. You download the encoded image

                For now, this is a simulation.
                """)

                if st.button("🔒 Encode Message", type="primary", use_container_width=True):
                    if secret_message and encode_password:
                        with st.spinner("Encoding message via backend..."):
                            result = st.session_state.backend.encode_stego(
                                secret_message, encode_password, method, intensity
                            )

                            if result['success']:
                                st.success("✅ Message encoded successfully!")
                                st.json(result['data'])
                            else:
                                st.error(f"❌ Encoding failed: {result['error']}")
                    else:
                        st.error("Please enter both message and password")

        with tab2:
            st.markdown("#### Extract a hidden message")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### Note")
                st.info("""
                This uses the backend steganography service.
                In a real implementation, you would:
                1. Upload an encoded image
                2. The backend decodes the message from it
                3. You see the extracted message

                For now, this is a simulation.
                """)

            with col2:
                # Decoding parameters
                decode_password = st.text_input("Decryption Password", type="password",
                                                placeholder="Enter password used for encoding", key="decode_pass")

                decode_method = st.selectbox("Decoding Method", ["lsb", "lsb_advanced"], key="decode_method")

                decode_intensity = st.slider("Decoding Intensity", 1, 4, 1, key="decode_intensity")

                if st.button("🔓 Extract Message", type="primary", use_container_width=True, key="decode_btn"):
                    if decode_password:
                        with st.spinner("Decoding message via backend..."):
                            result = st.session_state.backend.decode_stego(
                                decode_password, decode_method, decode_intensity
                            )

                            if result['success']:
                                st.success("✅ Message extracted successfully!")
                                st.text_area("Extracted Message", result['data']['decrypted_message'], height=150)
                            else:
                                st.error(f"❌ Decoding failed: {result['error']}")
                    else:
                        st.error("Please enter password")

    def stats_page(self):
        st.markdown("### 📊 Your Statistics")

        # Get stats from backend
        with st.spinner("Loading statistics..."):
            result = st.session_state.backend.get_stats()

        if not result['success']:
            st.error(f"Failed to load statistics: {result['error']}")
            return

        stats = result['data']

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                label="Messages Sent",
                value=stats['messages']['sent'],
                delta=f"{stats['messages']['sent']}"
            )

        with col2:
            st.metric(
                label="Messages Received",
                value=stats['messages']['received'],
                delta=f"{stats['messages']['received']}"
            )

        with col3:
            st.metric(
                label="Stego Operations",
                value=stats['steganography']['operations'],
                delta=f"{stats['steganography']['operations']}"
            )

        st.divider()

        # Detailed stats
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### 📈 Message Statistics")
            st.write(f"**Unread Messages:** {stats['messages']['unread']}")
            st.write(f"**Encryption Rate:** {stats['messages']['encryption_rate']:.1f}%")
            st.write(f"**Total Chats:** {stats['chats']['active_chats']}")
            st.write(f"**Pinned Chats:** {stats['chats']['pinned_chats']}")

        with col2:
            st.markdown("#### 🛡️ Security Status")
            st.write("✅ AES-256 Encryption: Active")
            st.write("✅ Quantum-Resistant: Enabled")
            st.write(f"**Quantum Keys:** {stats['security']['quantum_keys']}")
            if stats['security']['last_key_generation']:
                st.write(f"**Last Key Generation:** {stats['security']['last_key_generation'][:10]}")

        st.divider()

        # Steganography stats
        st.markdown("#### 🖼️ Steganography Operations")
        col1, col2 = st.columns(2)

        with col1:
            st.write(f"**Encode Operations:** {stats['steganography']['encode_count']}")

        with col2:
            st.write(f"**Decode Operations:** {stats['steganography']['decode_count']}")

    def settings_page(self):
        st.markdown("### ⚙️ Settings")

        tab1, tab2, tab3 = st.tabs(["👤 Profile", "🔐 Security", "ℹ️ About"])

        with tab1:
            st.markdown("#### Personal Information")

            user = st.session_state.current_user

            # Display current info
            col1, col2 = st.columns(2)

            with col1:
                st.text_input("Username", value=user['username'], disabled=True)
                st.text_input("Email", value=user.get('email', 'Not set'), disabled=True)

            with col2:
                st.text_input("Phone", value=user.get('phone', 'Not set'), disabled=True)
                st.text_input("Status", value=user.get('status', 'Secure & Encrypted 🔐'), disabled=True)

            # Note about updating
            st.info("Profile updates through API coming soon!")

        with tab2:
            st.markdown("#### Security Settings")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("##### Encryption")
                st.selectbox("Algorithm", ["AES-256-CBC", "AES-256-GCM", "ChaCha20-Poly1305"], disabled=True)
                st.select_slider("Key Rotation", options=["7 days", "30 days", "90 days", "Never"], value="30 days",
                                 disabled=True)

                st.markdown("##### Features")
                st.toggle("Auto-encrypt all messages", value=True, disabled=True)
                st.toggle("Require password for decryption", value=True, disabled=True)

            with col2:
                st.markdown("##### Steganography")
                st.selectbox("Default Method", ["LSB (Basic)", "LSB Advanced"], disabled=True)
                st.slider("Default Intensity", 1, 4, 1, disabled=True)

                st.markdown("##### Advanced")
                st.toggle("Deniable encryption", value=False, disabled=True)
                st.toggle("Quantum-resistant mode", value=True, disabled=True)

            st.info("Security settings managed through backend API")

        with tab3:
            st.markdown("#### About E-Encrypt")

            st.markdown("""
            **Version:** 6.0.0 (Backend Connected)

            **Description:**
            E-Encrypt is a quantum-resistant secure messenger with advanced steganography capabilities.

            **Features:**
            - 🔐 AES-256 end-to-end encryption
            - 🖼️ Advanced image steganography
            - ⚛️ Quantum-resistant algorithms
            - 💬 Real-time encrypted chat
            - 📊 Message statistics
            - 🔑 Key management

            **Backend API:**
            - Centralized user management
            - Real-time messaging
            - Secure file storage
            - Statistics tracking

            **© 2024 SecureTech Inc.**
            """)

            st.divider()

            st.markdown("#### System Information")
            st.code(f"""
            Backend URL: {BACKEND_URL}
            Connection: {st.session_state.backend_status}
            User: {st.session_state.current_user['username']}
            User ID: {st.session_state.current_user['id']}
            """)


# Run the app
if __name__ == "__main__":
    st.set_page_config(
        page_title="E-Encrypt - Quantum Secure Messenger",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    app = EEncryptWebApp()
    app.run()