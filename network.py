import socket
import threading
import json
import base64
import ssl
import select
import time
import uuid
from datetime import datetime
from cryptography.fernet import Fernet
import asyncio
import websockets


class P2PNetworkManager:
    """Peer-to-Peer networking with WebRTC support"""

    def __init__(self):
        self.peers = {}
        self.server = None
        self.is_running = False
        self.user_id = None
        self.message_callbacks = []
        self.webrtc_connections = {}

        # SSL context for secure connections
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE  # Self-signed certs

    def start(self, port=5050):
        """Start P2P server"""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server.bind(('0.0.0.0', port))
            self.server.listen(10)
            self.is_running = True

            print(f"✅ P2P Server started on port {port}")

            # Start accepting connections
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()

            # Start WebRTC signaling server
            self.start_webrtc_signaling()

        except Exception as e:
            print(f"❌ Failed to start server: {e}")

    def accept_connections(self):
        """Accept incoming connections"""
        while self.is_running:
            try:
                client_socket, address = self.server.accept()

                # Wrap with SSL
                secure_socket = self.ssl_context.wrap_socket(
                    client_socket,
                    server_side=True
                )

                print(f"🔗 New connection from {address}")

                # Handle client in new thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(secure_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()

            except Exception as e:
                print(f"❌ Connection error: {e}")

    def handle_client(self, client_socket, address):
        """Handle client communication"""
        client_id = None

        try:
            # Authentication phase
            auth_data = self.receive_data(client_socket)
            if not auth_data:
                return

            auth_info = json.loads(auth_data.decode())

            # Verify authentication
            client_id = self.authenticate_client(auth_info)
            if not client_id:
                client_socket.send(b"AUTH_FAILED")
                return

            client_socket.send(b"AUTH_SUCCESS")

            # Add to peers
            self.peers[client_id] = {
                'socket': client_socket,
                'address': address,
                'last_seen': time.time(),
                'public_key': auth_info.get('public_key')
            }

            print(f"✅ Client {client_id} authenticated")

            # Send peer list
            self.send_peer_list(client_socket)

            # Main communication loop
            while self.is_running:
                try:
                    # Check for data with timeout
                    ready = select.select([client_socket], [], [], 1)
                    if ready[0]:
                        data = self.receive_data(client_socket)
                        if not data:
                            break

                        # Process message
                        self.process_message(client_id, data)

                except Exception as e:
                    print(f"❌ Client handling error: {e}")
                    break

        except Exception as e:
            print(f"❌ Client error: {e}")
        finally:
            if client_id and client_id in self.peers:
                del self.peers[client_id]
            client_socket.close()
            print(f"🔌 Client {client_id if client_id else address} disconnected")

    def authenticate_client(self, auth_info):
        """Authenticate connecting client"""
        required_fields = ['user_id', 'auth_token', 'public_key', 'timestamp']

        # Check required fields
        for field in required_fields:
            if field not in auth_info:
                return None

        # Verify auth token (in real app, check against database)
        # For demo, accept all
        return auth_info['user_id']

    def connect_to_peer(self, peer_info):
        """Connect to another peer"""
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Wrap with SSL
            secure_socket = self.ssl_context.wrap_socket(
                peer_socket,
                server_hostname=peer_info['host']
            )

            secure_socket.connect((peer_info['host'], peer_info['port']))

            # Send authentication
            auth_data = {
                'user_id': self.user_id,
                'auth_token': self.generate_auth_token(),
                'public_key': self.get_public_key(),
                'timestamp': datetime.now().isoformat()
            }

            self.send_data(secure_socket, json.dumps(auth_data).encode())

            # Wait for response
            response = self.receive_data(secure_socket)
            if response == b"AUTH_SUCCESS":
                # Add to peers
                self.peers[peer_info['user_id']] = {
                    'socket': secure_socket,
                    'address': (peer_info['host'], peer_info['port']),
                    'last_seen': time.time(),
                    'public_key': peer_info.get('public_key')
                }

                print(f"✅ Connected to peer {peer_info['user_id']}")
                return True

        except Exception as e:
            print(f"❌ Connection error: {e}")

        return False

    def send_message(self, recipient_id, message, message_type="text", metadata=None):
        """Send message to specific peer"""
        if recipient_id in self.peers:
            try:
                peer_socket = self.peers[recipient_id]['socket']

                # Prepare message packet
                packet = {
                    'type': 'message',
                    'sender': self.user_id,
                    'recipient': recipient_id,
                    'message': message,
                    'message_type': message_type,
                    'timestamp': datetime.now().isoformat(),
                    'message_id': str(uuid.uuid4())
                }

                if metadata:
                    packet['metadata'] = metadata

                # Send via socket
                self.send_data(peer_socket, json.dumps(packet).encode())

                print(f"📤 Message sent to {recipient_id}")
                return True

            except Exception as e:
                print(f"❌ Send error: {e}")
                # Remove disconnected peer
                if recipient_id in self.peers:
                    del self.peers[recipient_id]

        return False

    def send_file(self, recipient_id, file_data, filename):
        """Send file to peer"""
        try:
            # Split file into chunks
            chunk_size = 1024 * 64  # 64KB chunks
            file_id = str(uuid.uuid4())

            for i in range(0, len(file_data), chunk_size):
                chunk = file_data[i:i + chunk_size]

                packet = {
                    'type': 'file_chunk',
                    'sender': self.user_id,
                    'recipient': recipient_id,
                    'file_id': file_id,
                    'filename': filename,
                    'chunk_index': i // chunk_size,
                    'total_chunks': (len(file_data) + chunk_size - 1) // chunk_size,
                    'data': base64.b64encode(chunk).decode(),
                    'timestamp': datetime.now().isoformat()
                }

                self.send_message(recipient_id, json.dumps(packet), "file")

            print(f"📁 File {filename} sent to {recipient_id}")
            return True

        except Exception as e:
            print(f"❌ File send error: {e}")
            return False

    def send_call_request(self, recipient_id, call_type, session_key):
        """Send voice/video call request"""
        packet = {
            'type': 'call_request',
            'sender': self.user_id,
            'recipient': recipient_id,
            'call_type': call_type,
            'session_key': session_key,
            'timestamp': datetime.now().isoformat()
        }

        return self.send_message(recipient_id, json.dumps(packet), "call")

    def broadcast(self, message, exclude_ids=None):
        """Broadcast message to all connected peers"""
        if exclude_ids is None:
            exclude_ids = []

        success_count = 0
        for peer_id in list(self.peers.keys()):
            if peer_id not in exclude_ids:
                if self.send_message(peer_id, message):
                    success_count += 1

        return success_count

    def process_message(self, sender_id, data):
        """Process incoming message"""
        try:
            message = json.loads(data.decode())
            msg_type = message.get('type')

            if msg_type == 'message':
                # Standard message
                for callback in self.message_callbacks:
                    callback(
                        sender_id,
                        message['message'],
                        message.get('message_type', 'text')
                    )

            elif msg_type == 'file_chunk':
                # File chunk
                self.handle_file_chunk(sender_id, message)

            elif msg_type == 'call_request':
                # Call request
                self.handle_call_request(sender_id, message)

            elif msg_type == 'webrtc_signal':
                # WebRTC signaling
                self.handle_webrtc_signal(sender_id, message)

            # Update last seen
            if sender_id in self.peers:
                self.peers[sender_id]['last_seen'] = time.time()

        except Exception as e:
            print(f"❌ Message processing error: {e}")

    def handle_file_chunk(self, sender_id, chunk_data):
        """Handle incoming file chunk"""
        # Implement file reassembly
        pass

    def handle_call_request(self, sender_id, call_data):
        """Handle incoming call request"""
        # Forward to UI layer
        for callback in self.message_callbacks:
            callback(sender_id, call_data, 'call_request')

    def handle_webrtc_signal(self, sender_id, signal_data):
        """Handle WebRTC signaling"""
        # Forward to appropriate WebRTC connection
        pass

    def set_message_callback(self, callback):
        """Set callback for incoming messages"""
        self.message_callbacks.append(callback)

    def send_data(self, socket, data):
        """Send data with length prefix"""
        # Prefix with data length
        length = len(data).to_bytes(4, 'big')
        socket.sendall(length + data)

    def receive_data(self, socket):
        """Receive data with length prefix"""
        try:
            # Read length
            length_bytes = socket.recv(4)
            if not length_bytes:
                return None

            length = int.from_bytes(length_bytes, 'big')

            # Read data
            data = b''
            while len(data) < length:
                chunk = socket.recv(min(4096, length - len(data)))
                if not chunk:
                    return None
                data += chunk

            return data

        except Exception as e:
            print(f"❌ Receive error: {e}")
            return None

    def send_peer_list(self, socket):
        """Send list of connected peers"""
        peer_list = []
        for peer_id, peer_info in self.peers.items():
            if peer_id != self.user_id:
                peer_list.append({
                    'user_id': peer_id,
                    'address': peer_info['address'][0],
                    'port': peer_info['address'][1],
                    'public_key': peer_info.get('public_key')
                })

        packet = {
            'type': 'peer_list',
            'peers': peer_list,
            'timestamp': datetime.now().isoformat()
        }

        self.send_data(socket, json.dumps(packet).encode())

    def generate_auth_token(self):
        """Generate authentication token"""
        import hmac
        import hashlib

        timestamp = str(int(time.time()))
        secret = "YOUR_SECRET_KEY"  # Should be stored securely

        return hmac.new(
            secret.encode(),
            (self.user_id + timestamp).encode(),
            hashlib.sha256
        ).hexdigest()

    def get_public_key(self):
        """Get user's public key"""
        try:
            with open("data/keys/public.pem", "rb") as f:
                return f.read().decode()
        except:
            return None

    def start_webrtc_signaling(self):
        """Start WebRTC signaling server"""

        async def signaling_server():
            async with websockets.serve(
                    self.handle_webrtc_websocket,
                    "localhost",
                    8765
            ):
                await asyncio.Future()  # Run forever

        # Start in background thread
        threading.Thread(
            target=lambda: asyncio.run(signaling_server()),
            daemon=True
        ).start()

    async def handle_webrtc_websocket(self, websocket, path):
        """Handle WebRTC WebSocket connections"""
        try:
            async for message in websocket:
                data = json.loads(message)
                await self.process_webrtc_signal(websocket, data)
        except Exception as e:
            print(f"WebRTC WebSocket error: {e}")

    async def process_webrtc_signal(self, websocket, signal_data):
        """Process WebRTC signaling messages"""
        # Implement WebRTC signaling
        pass

    def disconnect(self):
        """Disconnect from all peers"""
        self.is_running = False

        # Close all connections
        for peer_id, peer_info in list(self.peers.items()):
            try:
                peer_info['socket'].close()
            except:
                pass

        self.peers.clear()

        # Close server
        if self.server:
            self.server.close()

        print("🔌 Disconnected from all peers")