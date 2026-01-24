"""
🔒 E-Encrypt Desktop App v6.0 - WITH BACKEND CONNECTION
Run: python main_desktop_backend.py
"""

import os
import sys
import json
import requests
import threading
import hashlib
import base64
from datetime import datetime
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.core.window import Window
from kivy.properties import StringProperty, NumericProperty, ListProperty, BooleanProperty
from kivy.clock import Clock
from kivy.uix.filechooser import FileChooserListView
import websocket
import _thread
import time

# ==================== CONFIGURATION ====================
BACKEND_URL = "http://localhost:8000"  # Change if backend is elsewhere
WS_URL = "ws://localhost:8000/ws"  # WebSocket URL


# ==================== BACKEND CLIENT ====================
class BackendClient:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.token = None
        self.user_id = None
        self.username = None
        self.ws = None
        self.ws_connected = False

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
        self.ws_connected = False
        if self.ws:
            self.ws.close()
            self.ws = None

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

    def generate_quantum_keys(self):
        """Generate quantum keys"""
        url = f"{self.base_url}/api/quantum/generate-keys"
        data = {"algorithm": "quantum-resistant"}
        try:
            response = requests.post(url, json=data, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": "Failed to generate keys"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def upload_file(self, file_path, encrypted=True, password=None):
        """Upload a file"""
        url = f"{self.base_url}/api/files/upload"

        try:
            with open(file_path, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode()

            data = {
                "filename": os.path.basename(file_path),
                "file_data": file_data,
                "encrypted": encrypted,
                "encryption_key": password
            }

            response = requests.post(url, json=data, headers=self.get_headers(), timeout=60)
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": response.json().get("detail", "Upload failed")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def connect_websocket(self, on_message_callback):
        """Connect to WebSocket"""
        if not self.token or not self.user_id:
            return False

        def on_open(ws):
            self.ws_connected = True
            print("WebSocket connected")
            # Send authentication
            ws.send(json.dumps({"type": "auth", "token": self.token}))

        def on_message(ws, message):
            try:
                data = json.loads(message)
                on_message_callback(data)
            except:
                pass

        def on_error(ws, error):
            print(f"WebSocket error: {error}")
            self.ws_connected = False

        def on_close(ws, close_status_code, close_msg):
            print("WebSocket closed")
            self.ws_connected = False

        # Connect to WebSocket
        ws_url = f"{WS_URL}/{self.user_id}?token={self.token}"
        self.ws = websocket.WebSocketApp(
            ws_url,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close
        )

        # Start WebSocket in background thread
        wst = threading.Thread(target=self.ws.run_forever)
        wst.daemon = True
        wst.start()

        return True

    def send_typing(self, receiver_id, is_typing=True):
        """Send typing indicator"""
        if self.ws and self.ws_connected:
            data = {
                "type": "typing",
                "receiver_id": receiver_id,
                "is_typing": is_typing
            }
            self.ws.send(json.dumps(data))


# ==================== KIVY UI SCREENS ====================
class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        layout = BoxLayout(orientation='vertical', padding=50, spacing=20)

        # Logo
        logo = Label(text='🔐 E-Encrypt', font_size='48sp', color=(0.07, 0.55, 0.49, 1))
        layout.add_widget(logo)

        subtitle = Label(text='Quantum-Resistant Secure Messenger', font_size='16sp', color=(0.5, 0.5, 0.5, 1))
        layout.add_widget(subtitle)

        layout.add_widget(Label(size_hint_y=None, height=30))

        # Username input
        self.username = TextInput(
            hint_text='Username',
            size_hint_y=None,
            height=50,
            multiline=False,
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1)
        )
        layout.add_widget(self.username)

        # Password input
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

        # Login button
        login_btn = Button(
            text='Login',
            size_hint_y=None,
            height=50,
            background_color=(0.07, 0.55, 0.49, 1),
            color=(1, 1, 1, 1)
        )
        login_btn.bind(on_press=self.do_login)
        layout.add_widget(login_btn)

        # Register button
        register_btn = Button(
            text='Register',
            size_hint_y=None,
            height=50,
            background_color=(0.3, 0.3, 0.4, 1),
            color=(1, 1, 1, 1)
        )
        register_btn.bind(on_press=self.show_register)
        layout.add_widget(register_btn)

        # Quick login buttons
        layout.add_widget(Label(text='Quick Login:', size_hint_y=None, height=30, color=(0.7, 0.7, 0.7, 1)))

        quick_layout = GridLayout(cols=2, spacing=10, size_hint_y=None, height=100)

        test_users = ['alice', 'bob', 'charlie']
        for user in test_users:
            btn = Button(
                text=f'👤 {user.title()}',
                size_hint_y=None,
                height=45,
                background_color=(0.3, 0.5, 0.7, 1)
            )
            btn.bind(on_press=lambda x, u=user: self.quick_login(u))
            quick_layout.add_widget(btn)

        layout.add_widget(quick_layout)

        # Connection status
        self.status_label = Label(
            text='🔴 Not connected to backend',
            size_hint_y=None,
            height=30,
            color=(1, 0.3, 0.3, 1)
        )
        layout.add_widget(self.status_label)

        self.add_widget(layout)

        # Test backend connection
        Clock.schedule_once(self.test_backend_connection, 1)

    def test_backend_connection(self, dt):
        """Test if backend is reachable"""
        try:
            response = requests.get(f"{BACKEND_URL}/api/health", timeout=5)
            if response.status_code == 200:
                self.status_label.text = '🟢 Backend connected'
                self.status_label.color = (0.3, 1, 0.3, 1)
            else:
                self.status_label.text = '🟡 Backend responding but with error'
                self.status_label.color = (1, 1, 0.3, 1)
        except:
            self.status_label.text = '🔴 Cannot connect to backend. Make sure backend is running!'
            self.status_label.color = (1, 0.3, 0.3, 1)

    def quick_login(self, username):
        self.username.text = username
        self.password.text = 'password123'
        self.do_login(None)

    def do_login(self, instance):
        username = self.username.text.strip()
        password = self.password.text.strip()

        if not username or not password:
            self.show_popup('Error', 'Please enter username and password')
            return

        app = App.get_running_app()
        result = app.backend.login(username, password)

        if result['success']:
            app.current_user = result['data']['user']

            # Connect to WebSocket for real-time updates
            app.backend.connect_websocket(app.on_websocket_message)

            # Load chats
            app.sm.current = 'chats'
            app.sm.get_screen('chats').load_chats()
        else:
            self.show_popup('Login Failed', result['error'])

    def show_register(self, instance):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)

        content.add_widget(Label(text='Register New Account', color=(0, 0, 0, 1)))

        reg_username = TextInput(hint_text='Username', size_hint_y=None, height=40)
        content.add_widget(reg_username)

        reg_password = TextInput(hint_text='Password', password=True, size_hint_y=None, height=40)
        content.add_widget(reg_password)

        reg_confirm = TextInput(hint_text='Confirm Password', password=True, size_hint_y=None, height=40)
        content.add_widget(reg_confirm)

        reg_email = TextInput(hint_text='Email (optional)', size_hint_y=None, height=40)
        content.add_widget(reg_email)

        reg_phone = TextInput(hint_text='Phone (optional)', size_hint_y=None, height=40)
        content.add_widget(reg_phone)

        def do_register(instance):
            username = reg_username.text.strip()
            password = reg_password.text.strip()
            confirm = reg_confirm.text.strip()
            email = reg_email.text.strip() or None
            phone = reg_phone.text.strip() or None

            if not username or not password:
                self.show_popup('Error', 'Please enter username and password')
                return

            if password != confirm:
                self.show_popup('Error', 'Passwords do not match')
                return

            if len(password) < 6:
                self.show_popup('Error', 'Password must be at least 6 characters')
                return

            app = App.get_running_app()
            result = app.backend.register(username, password, email, phone)

            if result['success']:
                app.current_user = result['data']['user']

                # Connect to WebSocket
                app.backend.connect_websocket(app.on_websocket_message)

                popup.dismiss()
                app.sm.current = 'chats'
                app.sm.get_screen('chats').load_chats()
                self.show_popup('Success', f'Account created!\nWelcome {username}!')
            else:
                self.show_popup('Registration Failed', result['error'])

        register_btn = Button(text='Create Account', size_hint_y=None, height=40,
                              background_color=(0.07, 0.55, 0.49, 1))
        register_btn.bind(on_press=do_register)
        content.add_widget(register_btn)

        popup = Popup(title='Register', content=content, size_hint=(0.8, 0.6))
        popup.open()

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message, color=(0, 0, 0, 1)))

        btn = Button(text='OK', size_hint_y=None, height=40,
                     background_color=(0.07, 0.55, 0.49, 1))
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))
        btn.bind(on_press=popup.dismiss)
        content.add_widget(btn)
        popup.open()


class ChatsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        layout = BoxLayout(orientation='vertical')

        # Header
        header = BoxLayout(size_hint_y=None, height=60, padding=[10, 5])
        with header.canvas.before:
            Color(0.07, 0.55, 0.49, 1)
            Rectangle(pos=header.pos, size=header.size)

        self.title_label = Label(text='Chats', font_size='20sp', bold=True, color=(1, 1, 1, 1))
        header.add_widget(self.title_label)

        layout.add_widget(header)

        # Chats list
        self.chats_scroll = ScrollView()
        self.chats_layout = BoxLayout(orientation='vertical', size_hint_y=None, spacing=5, padding=[10, 10])
        self.chats_layout.bind(minimum_height=self.chats_layout.setter('height'))
        self.chats_scroll.add_widget(self.chats_layout)
        layout.add_widget(self.chats_scroll)

        # Bottom buttons
        bottom_box = BoxLayout(size_hint_y=None, height=60, spacing=10, padding=[10, 5])

        stegano_btn = Button(text='🖼️ Steganography', size_hint_x=0.5,
                             background_color=(0.2, 0.6, 0.8, 1))
        stegano_btn.bind(on_press=self.open_stegano)

        logout_btn = Button(text='🚪 Logout', size_hint_x=0.5,
                            background_color=(0.8, 0.2, 0.2, 1))
        logout_btn.bind(on_press=self.logout)

        bottom_box.add_widget(stegano_btn)
        bottom_box.add_widget(logout_btn)
        layout.add_widget(bottom_box)

        self.add_widget(layout)

    def on_pre_enter(self):
        self.load_chats()

    def load_chats(self):
        self.chats_layout.clear_widgets()
        app = App.get_running_app()

        if not app.current_user:
            return

        self.title_label.text = f'Chats - {app.current_user["username"]}'

        # Get chats from backend
        result = app.backend.get_chats()

        if not result['success']:
            error_label = Label(
                text=f'Error loading chats:\n{result["error"]}',
                size_hint_y=None,
                height=100,
                color=(1, 0.3, 0.3, 1)
            )
            self.chats_layout.add_widget(error_label)
            return

        chats = result['data']

        if not chats:
            empty_label = Label(
                text='No chats yet\nStart by selecting a contact!',
                size_hint_y=None,
                height=200,
                color=(0.7, 0.7, 0.7, 1),
                halign='center'
            )
            self.chats_layout.add_widget(empty_label)
        else:
            for chat in chats:
                self.add_chat_item(chat)

        # Add "New Chat" button
        new_chat_btn = Button(
            text='+ New Chat',
            size_hint_y=None,
            height=60,
            background_color=(0.07, 0.55, 0.49, 1),
            color=(1, 1, 1, 1)
        )
        new_chat_btn.bind(on_press=self.show_new_chat)
        self.chats_layout.add_widget(new_chat_btn)

    def add_chat_item(self, chat):
        other_user = chat['other_user']

        item = BoxLayout(orientation='horizontal', size_hint_y=None, height=70, padding=[10, 5], spacing=10)

        # Avatar
        avatar = Button(
            size_hint_x=None,
            width=50,
            background_normal='',
            background_color=self.hex_to_rgb(other_user['avatar_color'])
        )
        item.add_widget(avatar)

        # Chat info
        info_box = BoxLayout(orientation='vertical', spacing=2)

        name_label = Label(
            text=other_user['username'],
            size_hint_y=None,
            height=25,
            halign='left',
            color=(0, 0, 0, 1),
            bold=True
        )
        info_box.add_widget(name_label)

        last_msg = chat['last_message']['content'] if chat['last_message'] else 'No messages yet'
        msg_label = Label(
            text=last_msg,
            size_hint_y=None,
            height=20,
            halign='left',
            color=(0.5, 0.5, 0.5, 1)
        )
        info_box.add_widget(msg_label)

        status = '🟢 Online' if other_user['is_online'] else '⚫ Offline'
        status_label = Label(
            text=status,
            size_hint_y=None,
            height=15,
            halign='left',
            color=(0.7, 0.7, 0.7, 1),
            font_size='12sp'
        )
        info_box.add_widget(status_label)

        item.add_widget(info_box)

        # Unread count
        if chat['unread_count'] > 0:
            unread = Label(
                text=str(chat['unread_count']),
                size_hint_x=None,
                width=30,
                color=(1, 1, 1, 1),
                bold=True
            )
            with unread.canvas.before:
                Color(0.07, 0.55, 0.49, 1)
                Ellipse(pos=unread.pos, size=unread.size)
            item.add_widget(unread)

        # Open chat button
        open_btn = Button(
            text='→',
            size_hint_x=None,
            width=40,
            background_color=(0.07, 0.55, 0.49, 0.8)
        )
        open_btn.bind(on_press=lambda x, c=chat: self.open_chat(c))
        item.add_widget(open_btn)

        self.chats_layout.add_widget(item)

    def hex_to_rgb(self, hex_color):
        hex_color = hex_color.lstrip('#')
        r = int(hex_color[0:2], 16) / 255.0
        g = int(hex_color[2:4], 16) / 255.0
        b = int(hex_color[4:6], 16) / 255.0
        return [r, g, b, 1]

    def open_chat(self, chat):
        app = App.get_running_app()
        app.current_chat = chat

        # Load chat screen
        chat_screen = self.manager.get_screen('chat')
        chat_screen.load_chat()

        self.manager.current = 'chat'

    def show_new_chat(self, instance):
        app = App.get_running_app()

        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text='Select user to chat with:'))

        # Get all users
        result = app.backend.get_users()

        if not result['success']:
            self.show_popup('Error', result['error'])
            return

        users = result['data']

        scroll = ScrollView(size_hint_y=None, height=300)
        users_box = BoxLayout(orientation='vertical', size_hint_y=None)
        users_box.bind(minimum_height=users_box.setter('height'))

        for user in users:
            btn = Button(
                text=f"{user['username']} - {user['status']}",
                size_hint_y=None,
                height=50
            )
            btn.bind(on_press=lambda x, u=user: self.create_new_chat(u, popup))
            users_box.add_widget(btn)

        scroll.add_widget(users_box)
        content.add_widget(scroll)

        popup = Popup(title='New Chat', content=content, size_hint=(0.8, 0.7))
        popup.open()

    def create_new_chat(self, user, popup):
        popup.dismiss()

        # Create chat object
        chat = {
            'chat_id': f"new_{user['id']}",
            'other_user': user,
            'last_message': None,
            'unread_count': 0
        }

        app = App.get_running_app()
        app.current_chat = chat

        # Load chat screen
        chat_screen = self.manager.get_screen('chat')
        chat_screen.load_chat()

        self.manager.current = 'chat'

    def open_stegano(self, instance):
        self.manager.current = 'stegano'

    def logout(self, instance):
        app = App.get_running_app()
        app.backend.logout()
        app.current_user = None
        app.current_chat = None
        self.manager.current = 'login'

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message, color=(0, 0, 0, 1)))

        btn = Button(text='OK', size_hint_y=None, height=40,
                     background_color=(0.07, 0.55, 0.49, 1))
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))
        btn.bind(on_press=popup.dismiss)
        content.add_widget(btn)
        popup.open()


class ChatScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        layout = BoxLayout(orientation='vertical')

        # Header
        self.header = BoxLayout(size_hint_y=None, height=60, padding=[10, 5])
        with self.header.canvas.before:
            Color(0.07, 0.55, 0.49, 1)
            Rectangle(pos=self.header.pos, size=self.header.size)

        back_btn = Button(text='←', size_hint_x=None, width=40,
                          background_normal='', background_color=(0, 0, 0, 0),
                          color=(1, 1, 1, 1))
        back_btn.bind(on_press=self.go_back)
        self.header.add_widget(back_btn)

        self.contact_info = BoxLayout(orientation='vertical', spacing=2)
        self.contact_name = Label(text='', font_size='16sp', bold=True,
                                  color=(1, 1, 1, 1), halign='left')
        self.contact_status = Label(text='', font_size='12sp',
                                    color=(0.9, 0.95, 1, 0.8), halign='left')
        self.contact_info.add_widget(self.contact_name)
        self.contact_info.add_widget(self.contact_status)
        self.header.add_widget(self.contact_info)

        layout.add_widget(self.header)

        # Messages area
        self.messages_scroll = ScrollView()
        self.messages_layout = BoxLayout(orientation='vertical', size_hint_y=None,
                                         spacing=5, padding=[10, 10])
        self.messages_layout.bind(minimum_height=self.messages_layout.setter('height'))
        self.messages_scroll.add_widget(self.messages_layout)
        layout.add_widget(self.messages_scroll)

        # Input area
        input_box = BoxLayout(size_hint_y=None, height=60, padding=[10, 5], spacing=10)

        self.message_input = TextInput(
            hint_text='Type a message...',
            multiline=False,
            background_normal='',
            background_color=(1, 1, 1, 0.2),
            foreground_color=(1, 1, 1, 1)
        )

        send_btn = Button(text='Send', size_hint_x=None, width=80,
                          background_color=(0.07, 0.55, 0.49, 1),
                          color=(1, 1, 1, 1))
        send_btn.bind(on_press=self.send_message)

        input_box.add_widget(self.message_input)
        input_box.add_widget(send_btn)
        layout.add_widget(input_box)

        self.add_widget(layout)

        # Typing indicator
        self.typing_label = Label(
            text='',
            size_hint_y=None,
            height=20,
            color=(0.5, 0.5, 0.5, 0.7),
            font_size='12sp'
        )
        layout.add_widget(self.typing_label)

    def on_pre_enter(self):
        self.load_chat()

    def load_chat(self):
        self.messages_layout.clear_widgets()

        app = App.get_running_app()
        if not app.current_user or not app.current_chat:
            return

        chat = app.current_chat
        other_user = chat['other_user']

        self.contact_name.text = other_user['username']
        self.contact_status.text = '🟢 Online' if other_user['is_online'] else '⚫ Offline'

        # Get messages from backend
        result = app.backend.get_chat_messages(other_user['id'])

        if not result['success']:
            error_label = Label(
                text=f'Error loading messages:\n{result["error"]}',
                size_hint_y=None,
                height=100,
                color=(1, 0.3, 0.3, 1)
            )
            self.messages_layout.add_widget(error_label)
            return

        messages = result['data']

        if not messages:
            welcome = Label(
                text=f'Start chatting with {other_user["username"]}!',
                size_hint_y=None,
                height=100,
                color=(0.7, 0.7, 0.7, 1),
                halign='center'
            )
            self.messages_layout.add_widget(welcome)
        else:
            for msg in messages:
                self.add_message(msg)

        # Scroll to bottom
        Clock.schedule_once(self.scroll_to_bottom, 0.1)

    def add_message(self, message):
        if message['is_me']:
            # My message - right aligned
            bubble = BoxLayout(orientation='vertical', size_hint=(0.7, None),
                               padding=[10, 5], spacing=2)
            bubble.height = 60

            with bubble.canvas.before:
                Color(0.07, 0.55, 0.49, 0.9)
                RoundedRectangle(pos=bubble.pos, size=bubble.size, radius=[10])

            content = message['content']
            if message.get('encrypted'):
                content = '🔒 ' + content

            msg_label = Label(
                text=content,
                size_hint_y=None,
                height=40,
                color=(1, 1, 1, 1),
                halign='left'
            )
            bubble.add_widget(msg_label)

            container = BoxLayout(orientation='horizontal')
            container.add_widget(Label(size_hint_x=0.3))
            container.add_widget(bubble)

        else:
            # Their message - left aligned
            bubble = BoxLayout(orientation='vertical', size_hint=(0.7, None),
                               padding=[10, 5], spacing=2)
            bubble.height = 60

            with bubble.canvas.before:
                Color(0.8, 0.8, 0.8, 0.9)
                RoundedRectangle(pos=bubble.pos, size=bubble.size, radius=[10])

            sender_label = Label(
                text=message.get('sender_name', 'User'),
                size_hint_y=None,
                height=20,
                color=(0.3, 0.3, 0.3, 1),
                bold=True,
                halign='left'
            )
            bubble.add_widget(sender_label)

            content = message['content']
            if message.get('encrypted'):
                content = '🔒 Encrypted message'
                # Add decrypt button
                decrypt_btn = Button(
                    text='Decrypt',
                    size_hint_y=None,
                    height=30,
                    background_color=(0.3, 0.6, 0.9, 0.8)
                )
                decrypt_btn.bind(on_press=lambda x, m=message: self.decrypt_message(m))
                bubble.add_widget(decrypt_btn)
                bubble.height += 35

            msg_label = Label(
                text=content,
                size_hint_y=None,
                height=40,
                color=(0, 0, 0, 1),
                halign='left'
            )
            bubble.add_widget(msg_label)

            container = BoxLayout(orientation='horizontal')
            container.add_widget(bubble)
            container.add_widget(Label(size_hint_x=0.3))

        self.messages_layout.add_widget(container)

    def send_message(self, instance):
        message = self.message_input.text.strip()
        if not message:
            return

        app = App.get_running_app()
        if not app.current_user or not app.current_chat:
            return

        other_user_id = app.current_chat['other_user']['id']

        # Send typing stop
        app.backend.send_typing(other_user_id, False)

        # Send message to backend
        result = app.backend.send_message(other_user_id, message)

        if result['success']:
            # Add message to UI immediately
            msg_data = {
                'id': result['data']['message_id'],
                'sender_id': app.current_user['id'],
                'content': message,
                'encrypted': False,
                'is_me': True
            }
            self.add_message(msg_data)

            self.message_input.text = ''
            Clock.schedule_once(self.scroll_to_bottom, 0.1)
        else:
            self.show_popup('Error', f'Failed to send message: {result["error"]}')

    def decrypt_message(self, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)

        content.add_widget(Label(text='Enter decryption password:'))

        password_input = TextInput(
            hint_text='Password',
            password=True,
            size_hint_y=None,
            height=40
        )
        content.add_widget(password_input)

        def decrypt(instance):
            password = password_input.text.strip()
            if not password:
                return

            # In real app, would decrypt using encryption key
            self.show_popup('Decrypted', f'Decryption would happen here with password: {password}')
            popup.dismiss()

        decrypt_btn = Button(text='Decrypt', size_hint_y=None, height=40,
                             background_color=(0.07, 0.55, 0.49, 1))
        decrypt_btn.bind(on_press=decrypt)
        content.add_widget(decrypt_btn)

        popup = Popup(title='Decrypt Message', content=content, size_hint=(0.8, 0.4))
        popup.open()

    def scroll_to_bottom(self, dt):
        if self.messages_layout.height > self.messages_scroll.height:
            self.messages_scroll.scroll_y = 0

    def go_back(self, instance):
        self.manager.current = 'chats'

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message, color=(0, 0, 0, 1)))

        btn = Button(text='OK', size_hint_y=None, height=40,
                     background_color=(0.07, 0.55, 0.49, 1))
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))
        btn.bind(on_press=popup.dismiss)
        content.add_widget(btn)
        popup.open()


class SteganographyScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        layout = BoxLayout(orientation='vertical', padding=20, spacing=15)

        # Title
        title = Label(text='🖼️ Steganography', font_size='24sp', color=(0.07, 0.55, 0.49, 1))
        layout.add_widget(title)

        # Mode selection
        mode_box = BoxLayout(size_hint_y=None, height=50, spacing=10)

        self.encode_btn = Button(
            text='🔒 Hide Message',
            background_color=(0.2, 0.6, 0.8, 1)
        )
        self.encode_btn.bind(on_press=self.show_encode)

        self.decode_btn = Button(
            text='🔓 Extract Message',
            background_color=(0.07, 0.55, 0.49, 1)  # Green as requested
        )
        self.decode_btn.bind(on_press=self.show_decode)

        mode_box.add_widget(self.encode_btn)
        mode_box.add_widget(self.decode_btn)
        layout.add_widget(mode_box)

        # Content area
        self.content_area = BoxLayout(orientation='vertical', spacing=10)
        layout.add_widget(self.content_area)

        # Back button
        back_btn = Button(
            text='← Back to Chats',
            size_hint_y=None,
            height=50,
            background_color=(0.8, 0.2, 0.2, 1)
        )
        back_btn.bind(on_press=self.go_back)
        layout.add_widget(back_btn)

        self.add_widget(layout)

        # Show encode by default
        self.show_encode(None)

    def show_encode(self, instance):
        self.content_area.clear_widgets()

        encode_box = BoxLayout(orientation='vertical', spacing=10)

        # Message input
        encode_box.add_widget(Label(text='Message to hide:', size_hint_y=None, height=30))

        self.encode_message = TextInput(
            hint_text='Type your secret message...',
            multiline=True,
            size_hint_y=None,
            height=100
        )
        encode_box.add_widget(self.encode_message)

        # Password
        encode_box.add_widget(Label(text='Password:', size_hint_y=None, height=30))

        self.encode_password = TextInput(
            hint_text='Enter strong password',
            password=True,
            size_hint_y=None,
            height=45
        )
        encode_box.add_widget(self.encode_password)

        # Image selection
        select_btn = Button(
            text='Select Image',
            size_hint_y=None,
            height=45,
            background_color=(0.4, 0.6, 0.8, 1)
        )
        select_btn.bind(on_press=self.select_encode_image)
        encode_box.add_widget(select_btn)

        self.encode_image_label = Label(
            text='No image selected',
            size_hint_y=None,
            height=30,
            color=(0.7, 0.7, 0.7, 1)
        )
        encode_box.add_widget(self.encode_image_label)

        # Encode button
        encode_action_btn = Button(
            text='🔒 Hide Message',
            size_hint_y=None,
            height=55,
            background_color=(0.2, 0.8, 0.4, 1),
            bold=True
        )
        encode_action_btn.bind(on_press=self.encode_message_action)
        encode_box.add_widget(encode_action_btn)

        self.content_area.add_widget(encode_box)

    def show_decode(self, instance):
        self.content_area.clear_widgets()

        decode_box = BoxLayout(orientation='vertical', spacing=10)

        # Image selection
        decode_box.add_widget(Label(text='Select encoded image:', size_hint_y=None, height=30))

        select_btn = Button(
            text='Select Image',
            size_hint_y=None,
            height=45,
            background_color=(0.4, 0.6, 0.8, 1)
        )
        select_btn.bind(on_press=self.select_decode_image)
        decode_box.add_widget(select_btn)

        self.decode_image_label = Label(
            text='No image selected',
            size_hint_y=None,
            height=30,
            color=(0.7, 0.7, 0.7, 1)
        )
        decode_box.add_widget(self.decode_image_label)

        # Password
        decode_box.add_widget(Label(text='Password:', size_hint_y=None, height=30))

        self.decode_password = TextInput(
            hint_text='Enter password used for encoding',
            password=True,
            size_hint_y=None,
            height=45
        )
        decode_box.add_widget(self.decode_password)

        # Decode button - GREEN
        decode_action_btn = Button(
            text='🔓 Extract Message',
            size_hint_y=None,
            height=55,
            background_color=(0.07, 0.55, 0.49, 1),  # Green
            bold=True
        )
        decode_action_btn.bind(on_press=self.decode_message_action)
        decode_box.add_widget(decode_action_btn)

        # Result display
        self.decode_result = Label(
            text='',
            size_hint_y=None,
            height=150,
            color=(0, 0, 0, 1)
        )
        decode_box.add_widget(self.decode_result)

        self.content_area.add_widget(decode_box)

    def select_encode_image(self, instance):
        content = BoxLayout(orientation='vertical')
        filechooser = FileChooserListView()
        content.add_widget(filechooser)

        def select(btn):
            if filechooser.selection:
                self.encode_image_path = filechooser.selection[0]
                self.encode_image_label.text = f'Selected: {os.path.basename(self.encode_image_path)}'
                popup.dismiss()

        select_btn = Button(text='Select', size_hint_y=None, height=40)
        select_btn.bind(on_press=select)
        content.add_widget(select_btn)

        popup = Popup(title='Select Image', content=content, size_hint=(0.9, 0.9))
        popup.open()

    def select_decode_image(self, instance):
        content = BoxLayout(orientation='vertical')
        filechooser = FileChooserListView()
        content.add_widget(filechooser)

        def select(btn):
            if filechooser.selection:
                self.decode_image_path = filechooser.selection[0]
                self.decode_image_label.text = f'Selected: {os.path.basename(self.decode_image_path)}'
                popup.dismiss()

        select_btn = Button(text='Select', size_hint_y=None, height=40)
        select_btn.bind(on_press=select)
        content.add_widget(select_btn)

        popup = Popup(title='Select Image', content=content, size_hint=(0.9, 0.9))
        popup.open()

    def encode_message_action(self, instance):
        if not hasattr(self, 'encode_image_path'):
            self.show_popup('Error', 'Please select an image first')
            return

        message = self.encode_message.text.strip()
        password = self.encode_password.text.strip()

        if not message:
            self.show_popup('Error', 'Please enter a message')
            return

        if not password:
            self.show_popup('Error', 'Please enter a password')
            return

        # Show loading
        loading_popup = Popup(title='Processing',
                              content=Label(text='Encoding message...'),
                              size_hint=(0.6, 0.3))
        loading_popup.open()

        # Send to backend
        app = App.get_running_app()
        result = app.backend.encode_stego(message, password)

        loading_popup.dismiss()

        if result['success']:
            self.show_popup('Success',
                            f'✅ Message encoded successfully!\n\n'
                            f'Operation ID: {result["data"]["operation_id"]}\n'
                            f'Method: {result["data"]["method"]}\n'
                            f'Note: {result["data"]["note"]}')
        else:
            self.show_popup('Error', f'❌ Failed to encode: {result["error"]}')

    def decode_message_action(self, instance):
        password = self.decode_password.text.strip()

        if not password:
            self.show_popup('Error', 'Please enter a password')
            return

        # Show loading
        loading_popup = Popup(title='Processing',
                              content=Label(text='Decoding message...'),
                              size_hint=(0.6, 0.3))
        loading_popup.open()

        # Send to backend
        app = App.get_running_app()
        result = app.backend.decode_stego(password)

        loading_popup.dismiss()

        if result['success']:
            self.decode_result.text = f'✅ Message extracted:\n\n{result["data"]["decrypted_message"]}'
        else:
            self.decode_result.text = f'❌ Failed to extract: {result["error"]}'

    def go_back(self, instance):
        self.manager.current = 'chats'

    def show_popup(self, title, message):
        content = BoxLayout(orientation='vertical', spacing=10, padding=20)
        content.add_widget(Label(text=message, color=(0, 0, 0, 1)))

        btn = Button(text='OK', size_hint_y=None, height=40,
                     background_color=(0.07, 0.55, 0.49, 1))
        popup = Popup(title=title, content=content, size_hint=(0.7, 0.4))
        btn.bind(on_press=popup.dismiss)
        content.add_widget(btn)
        popup.open()


# ==================== MAIN APP ====================
class EEncryptDesktopApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.backend = BackendClient()
        self.current_user = None
        self.current_chat = None
        self.sm = ScreenManager()

        Window.size = (400, 700)
        Window.minimum_width = 400
        Window.minimum_height = 600
        Window.clearcolor = (0.95, 0.95, 0.95, 1)

    def build(self):
        self.title = 'E-Encrypt - Secure Messenger (Backend Connected)'

        # Add screens
        self.sm.add_widget(LoginScreen(name='login'))
        self.sm.add_widget(ChatsScreen(name='chats'))
        self.sm.add_widget(ChatScreen(name='chat'))
        self.sm.add_widget(SteganographyScreen(name='stegano'))

        return self.sm

    def on_websocket_message(self, data):
        """Handle incoming WebSocket messages"""
        message_type = data.get('type')

        if message_type == 'new_message':
            # New message received
            Clock.schedule_once(lambda dt: self.handle_new_message(data))
        elif message_type == 'typing':
            # Typing indicator
            Clock.schedule_once(lambda dt: self.handle_typing(data))
        elif message_type == 'user_status':
            # User online/offline status
            Clock.schedule_once(lambda dt: self.handle_user_status(data))

    def handle_new_message(self, data):
        """Handle new message from WebSocket"""
        # If we're in the chat screen with this user, add the message
        if self.current_chat and self.current_chat['other_user']['id'] == data['sender_id']:
            chat_screen = self.sm.get_screen('chat')

            msg_data = {
                'id': data['message_id'],
                'sender_id': data['sender_id'],
                'sender_name': data['sender_username'],
                'content': data['content'],
                'encrypted': data['encrypted'],
                'is_me': False
            }

            chat_screen.add_message(msg_data)
            chat_screen.scroll_to_bottom(0)

    def handle_typing(self, data):
        """Handle typing indicator"""
        # Update typing indicator if we're in the right chat
        if self.current_chat and self.current_chat['other_user']['id'] == data['sender_id']:
            chat_screen = self.sm.get_screen('chat')
            if data['is_typing']:
                chat_screen.typing_label.text = f"{self.current_chat['other_user']['username']} is typing..."
            else:
                chat_screen.typing_label.text = ''

    def handle_user_status(self, data):
        """Handle user online/offline status"""
        # Update status in chats screen
        chats_screen = self.sm.get_screen('chats')
        chats_screen.load_chats()


def run_desktop_app():
    """Run the desktop application"""
    print("""
    ╔══════════════════════════════════════════╗
    ║     E-Encrypt Desktop (Backend Mode)    ║
    ║    Quantum-Resistant Secure Messenger   ║
    ╚══════════════════════════════════════════╝

    🔗 Backend Connection: {}
    ✅ Features:
    • Real-time messaging via backend
    • User registration/login
    • Steganography encoding/decoding
    • Green decode buttons
    • WebSocket real-time updates

    🚀 Quick Start:
    1. Make sure backend is running on {}
    2. Login with:
       • Username: alice, bob, charlie, david, emma
       • Password: password123

    3. OR create new account

    📡 Connection Status shown on login screen
    """.format(BACKEND_URL, BACKEND_URL))

    # Check backend connection
    try:
        response = requests.get(f"{BACKEND_URL}/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend connection successful!")
        else:
            print("⚠️  Backend responding but with error")
    except:
        print("❌ Cannot connect to backend!")
        print("   Make sure the backend server is running:")
        print("   python backend_api.py")
        print("\n   Or start it with: python run_backend.py")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            return

    EEncryptDesktopApp().run()


if __name__ == '__main__':
    run_desktop_app()