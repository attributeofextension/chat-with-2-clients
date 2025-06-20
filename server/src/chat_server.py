import socket
import threading
import json
import sys
import os
import ssl
from pymongo import MongoClient
from datetime import datetime, timezone
import queue
from bson.objectid import ObjectId
import bcrypt
import time

MONGO_HOST = os.getenv("MONGO_HOST", "mongo")
MONGO_PORT = int(os.getenv("MONGO_PORT", "27017"))
MONGO_USERNAME = os.getenv("MONGO_USERNAME")
MONGO_PASSWORD = os.getenv("MONGO_PASSWORD")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", 'chat_app_db')

CERT_FILE = "/app/certs/server.crt"
KEY_FILE = "/app/certs/server.key"
CLIENT_CA_CERTS = "/app/certs/server.crt"

mongo_client = None
db = None
users_collection = None
sessions_collection = None
messages_collection = None

def init_mongodb():
    global mongo_client, db, users_collection, sessions_collection, messages_collection
    try:
        if MONGO_USERNAME and MONGO_PASSWORD:
            mongo_client = MongoClient(MONGO_HOST, MONGO_PORT, username=MONGO_USERNAME, password=MONGO_PASSWORD, authSource=MONGO_DB_NAME)
        else:
            raise Exception("MONGO_USERNAME and MONGO_PASSWORD must be set.")

        mongo_client.admin.command('ping')
        print(f"Successfully connected to MongoDB at {MONGO_HOST}:{MONGO_PORT} as user '{MONGO_USERNAME}'.")

        db = mongo_client[MONGO_DB_NAME]
        users_collection = db['users']
        sessions_collection = db['sessions']
        messages_collection = db['messages']

        print(f"Using database: {MONGO_DB_NAME}")
        print("Collections: users, sessions, messages are ready.")

        return True
    except Exception as e:
        print(f"ERROR: Failed to connect to MongoDB or access collections: {e}")
        return False

def register_user(username, password):
    if not username or not password:
        return False, "Username and password cannot be empty."

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        users_collection.insert_one({
            "username": username,
            "password_hash": hashed_password,
            "created_at": datetime.now(timezone.utc)
        })
        print(f"User '{username}' registered successfully.")
        return True, "Registration successful."
    except Exception as e:
        if "duplicate key error" in str(e):
            return False, "Username already exists."
        print(f"ERROR: Failed to register user '{username}': {e}")
        return False, "Registration failed due to a server error."

def authenticate_user(username, password):
    user = users_collection.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
        print(f"User '{username}' authenticated successfully.")
        return True, user
    print(f"Authentication failed for user '{username}'.")
    return False, None

def store_message(session_id, sender_username, receiver_usernames, content):
    try:
        messages_collection.insert_one({
            "sessionId": session_id,
            "sender": sender_username,
            "receivers": receiver_usernames,
            "content": content,
            "timestamp": datetime.now(timezone.utc)
        })
        print(f"Message from '{sender_username}' to [{', '.join(receiver_usernames)}] stored.")
        return True
    except Exception as e:
        print(f"ERROR: Failed to store message: {e}")
        return False


def send_message(conn, message_type, content):
    msg_dict = {"type": message_type, "content": content}
    try:
        data = json.dumps(msg_dict).encode("utf-8")
        conn.sendall(data + b"\n")
        return True
    except socket.error as e:
        print(f"ERROR: Failed to send message to {conn.getpeername() if conn.getpeername() else 'disconnected client'}: {e}")
        return False
    except TypeError as e:
        print(f"ERROR: TypeError during JSON serialization for {conn.getpeername() if conn.getpeername() else 'disconnected client'}: {e}")
        return False

def receive_message(conn):
    buffer = b''
    conn.settimeout(5)

    while True:
        try:
            chunk = conn.recv(4096)
            if not chunk:
                print(f"DEBUG: Client {conn.getpeername() if conn.getpeername() else 'unknown'} disconnected.")
                return None
            buffer += chunk
            if b'\n' in buffer:
                msg_bytes, buffer = buffer.split(b'\n', 1)
                try:
                    return json.loads(msg_bytes.decode("utf-8"))
                except json.JSONDecodeError:
                    peer_info = 'disconnected client'
                    try:
                        peer_info = conn.getpeername()
                    except OSError:
                        pass
                    print("WARNING: Malformed JSON from " + peer_info + ": " + msg_bytes.decode(encoding="utf-8", errors='ignore'))
                    continue
        except socket.timeout:
            pass
        except socket.error as e:
            print(f"ERROR: Socket error during receive from {conn.getpeername() if conn.getpeername() else 'unknown'}: {e}")
            return None
        except Exception as e:
            print(f"ERROR: Unexpected error during receive from {conn.getpeername() if conn.getpeername() else 'unknown'}: {e}")
            return None

authenticated_client_queue = queue.Queue()

class AuthenticationHandler(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__()
        self.conn = conn
        self.addr = addr
        print(f"Authentication handler started for {self.addr}")

    def run(self):
        try:
            if not send_message(self.conn, "auth_prompt", "Please authenticate. {'type': 'auth_request', 'action': 'login'/'register', 'username': '...', 'password': '...')"):
                print(f"Client {self.addr} disconnected before auth prompt sent.")
                self.conn.close()
                return
            while True:
                auth_message = receive_message(self.conn)
                if auth_message is None:
                    print(f"Client {self.addr} disconnected before authentication response.")
                    self.conn.close()
                    return

                if auth_message.get("type") == "auth_request":
                    action = auth_message.get("content").get("action")
                    username = auth_message.get("content").get("username")
                    password = auth_message.get("content").get("password")

                    if action == "register":
                        success, msg = register_user(username, password)
                        if success:
                            auth_success, user_doc = authenticate_user(username, password)
                            if auth_success:
                                send_message(self.conn, "auth_response", f"Registration successful and logged in as {username}.")
                                print(f"Client {self.addr} registered and logged in as {username}")
                                authenticated_client_queue.put(ChatClient(username, self.conn, self.addr))
                                break
                            else:
                                send_message(self.conn, "auth_response", "Registration successful, but failed to auto-login. Please try logging in.")
                        else:
                            send_message(self.conn, "auth_response", msg)
                            print(f"Client {self.addr} registration failed: {msg}")
                    elif action == "login":
                        auth_success, user_doc = authenticate_user(username, password)
                        if auth_success:
                            send_message(self.conn, "auth_response", f"Login successful as {username}.")
                            print(f"Client {self.addr} logged in as {username}.")
                            authenticated_client_queue.put(ChatClient(username, self.conn, self.addr))
                            break
                        else:
                            send_message(self.conn, "auth_response", "Login failed: Invalid username or password.")
                            print(f"Client {self.addr} login failed.")
                    else:
                        send_message(self.conn, "auth_response", "Invalid authentication action.")
                        print(f"Client {self.addr} sent invalid message type for auth: {auth_message.get('type')}, {auth_message.get('content')}")
                else:
                    send_message(self.conn, "auth_response", "Invalid authentication message type.")
                    print(f"Client {self.addr} sent invalid message type for auth: {auth_message.get('type')}")
        except Exception as e:
            print(f"ERROR: Exception in AuthenticationHandler for {self.addr}: {e}")
            try:
                self.conn.close()
            except socket.error:
                pass

class ChatClient:
    def __init__(self, username, conn, addr):
        self.username = username
        self.conn = conn
        self.addr = addr

    def __str__(self):
        return f"User {self.username} on {self.addr}"

class ChatMessage:
    def __init__(self, message_type, content):
        self.message_type = message_type
        self.content = content

class ChatSession(threading.Thread):
    def __init__(self, clients):
        super().__init__()
        self.session_id = ObjectId()
        self.active_clients_index = {client.username: client for client in clients}
        self.session_lock = threading.Lock()
        self.broadcast_queue = queue.Queue()
        self.session_active = True

        self.participants = sorted(client.username for client in clients)

        print(f"New chat session ({self.session_id}) initiated with participants: {self.participants}")

        self.create_db_session()

        if self.session_id:
            for username, client in self.active_clients_index.items():
                send_message(client.conn, "session_info", {
                    "sessionId": str(self.session_id),
                    "participants": self.participants,
                    "message": f"Welcome to the group chat! Your session ID is {self.session_id}."
                })
        else:
            print(f"WARNING: Session ID not available. Skipping initial info messages for new session.")

    def create_db_session(self):
        try:
            result = sessions_collection.insert_one({
                "participants": self. participants,
                "start_time": datetime.now(timezone.utc),
                "status": "active"
            })
            self.session_id = result.inserted_id
            print(f"MongoDB session created with ID: {self.session_id}")
        except Exception as e:
            print(f"ERROR: Failed to create MongoDB session: {e}")
            self.session_id = None

    def update_db_session_status(self, status):
        if self.session_id:
            try:
                sessions_collection.update_one(
                    {"_id": self.session_id },
                    {"$set": {"status": status, "end_time": datetime.now(timezone.utc) if status == "ended" else None}}
                )
                print(f"MongoDB session {self.session_id} updated to {status}.")
            except Exception as e:
                print(f"ERROR: Failed to update MongoDB session {self.session_id} status: {e}")

    def _client_listener_thread(self, client_conn, client_addr, username):
        print(f"Client listener thread started for {username} ({client_addr}) in session {self.session_id}")
        while self.session_active:
            message = receive_message(client_conn)
            if message is None:
                print(f"Client {username} ({client_addr}) disconnected from session {self.session_id}.")
                with self.session_lock:
                    if username in self.active_clients_index:
                        del self.active_clients_index[username]
                        print(f"Removed {username} from active clients. Remaining: {list(self.active_clients_index.keys())}")
                    if not self.active_clients_index and self.session_active:
                        self.session_active = False
                        print(f"No active clients left in session {self.session_id}. Signalling session end.")
                self.broadcast_queue.put({'type': 'info', 'sender': 'SERVER', 'content': f"{username} has left the chat."})
                break
            if message.get("type") == "chat":
                content = message.get("content")
                self.broadcast_queue.put({"type": "chat", "sender": username, "content": content})
            elif message.get("type") == "auth_request":
                print(f"WARNING: Unexpected auth_request from {username} ({client_addr}) during active session.")
            else:
                print(f"WARNING: Unknown message type '{message.get('type')}' from {username} ({client_addr})")

        try:
            client_conn.close()
        except socket.error:
            pass

    def _broadcast_thread_handler(self):
        print(f"Broadcast thread started for session {self.session_id}")
        while self.session_active or not self.broadcast_queue.empty():
            try:
                msg_to_broadcast = self.broadcast_queue.get(timeout=1)

                msg_type = msg_to_broadcast.get('type')
                sender = msg_to_broadcast.get('sender')
                content = msg_to_broadcast.get('content')

                formatted_message = f"[{sender}]: {content}" if msg_type == 'chat' else content

                if self.session_id and msg_type == 'chat':
                    with self.session_lock:
                        current_participants_usernames = list(self.active_clients_index.keys())

                    receivers_for_db = [p for p in current_participants_usernames if p != sender]
                    store_message(self.session_id, sender, receivers_for_db, content)
                elif msg_type == 'chat':
                    print(f"Not storing non-chat message type '{msg_type}' from broadcast queue.")

                with self.session_lock:
                    current_clients = list(self.active_clients_index.values())

                for client in current_clients:
                    conn = client.conn
                    client_username = client.username

                    if msg_type == 'chat' and client_username == sender:
                        continue

                    if not send_message(conn, msg_type, formatted_message):
                        print(f"Failed to send broadcast to {client_username}. Assuming disconnected.")

            except queue.Empty:
                pass
            except Exception as e:
                print(f"ERROR: Exception in broadcast thread for session {self.session_id}: {e}")
        print(f"Broadcast thread for session {self.session_id} ended.")

    def run(self):
        broadcast_thread = threading.Thread(target=self._broadcast_thread_handler, daemon=True)
        broadcast_thread.start()

        client_listener_threads = []
        initial_client_items = None
        with self.session_lock:
            initial_client_items = list(self.active_clients_index.items())

        for username, client in initial_client_items:
            conn = client.conn
            addr = client.addr
            thread = threading.Thread(target=self._client_listener_thread, args=(conn, addr, username), daemon=True)
            client_listener_threads.append(thread)
            thread.start()

        while self.session_active:
            time.sleep(0.5)

        print(f"Session {self.session_id} main thread detected session inactive. Joining listener threads...")
        for thread in client_listener_threads:
            if thread.is_alive():
                thread.join(timeout=1)

        if broadcast_thread.is_alive():
            broadcast_thread.join(timeout=2)

        self.update_db_session_status("ended")

        print(f"Chat session {self.session_id} fully terminated.")




def start_server(host, port):
    if not init_mongodb():
        print("Server cannot start without MongoDB connection. Exiting.")
        sys.exit(1)

    print(f"DEBUG: Creating ssl content...")
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    print(f"DEBUG: Attempting to load server certificate from: {CERT_FILE}")
    print(f"DEBUG: Attempting to load server private key from: {KEY_FILE}")
    try:
        ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)
        ssl_context.verify_mode = ssl.CERT_NONE
        print("DEBUG: Server SSL certificate and private key loaded successfully.")
    except FileNotFoundError as e:
        print(f"ERROR: SSL certificate or key file not found: {e}. Please ensure '{CERT_FILE}' and '{KEY_FILE}' exist.")
        sys.exit(1)
    except ssl.SSLError as e:
        print(f"ERROR: SSL context loading failed: {e}. Check ceertificate/key integrity and passphrase.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unexpected error loading SSL context: {e}")
        sys.exit(1)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(1.0)

    try:

        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"Chat Server listening on {host}:{port}")
        print("Waiting for clients to connect and authenticate...")

        ssl_server_socket = ssl_context.wrap_socket(server_socket, server_side=True)

        while True:
            try:
                conn, addr = ssl_server_socket.accept()
                print(f"New connection from {addr}. Spawning authentication handler.")

                auth_handler = AuthenticationHandler(conn, addr)
                auth_handler.start()

            except socket.timeout:
                pass
            except ssl.SSLError as e:
                print(f"SSL ERROR during accept or handshake: {e}. Client might have incompatible SSL settings.")
            except socket.error as e:
                print(f"ERROR: Socket error during server accept loop: {e}")
                break
            except KeyboardInterrupt:
                print("\nServer shutting down.")
                break
            except Exception as e:
                print(f"An unexpected general error occurred in server: {e}")
                break

            while authenticated_client_queue.qsize() >= 2:
                client1 = authenticated_client_queue.get()
                client2 = authenticated_client_queue.get()

                # test sockets before spawning chat session
                try:
                    # print(f"DEBUG: Checking connectivity for {client1.username} ({client1.addr})...")
                    # client1.conn.send(b'', 0)
                    # print(f"DEBUG: Checking connectivity for {client2.username} ({client2.addr})...")
                    # client2.conn.send(b'', 0)
                    # print(f"DEBUG: Both clients {client1.username} and {client2.username} appear connected. Starting session...")


                    chat_session = ChatSession([client1, client2])
                    chat_session.start()
                    print(f"Grouped [{', '.join([client1.__str__(),client2.__str__()])}]. New chat session started.")
                except socket.error as se:
                    print(f"WARNING: One or more clients ([{', '.join([client1.__str__(), client2.__str__()])}]) disconnected before chat session could start: {se}. Discarding group.")
                    try: client1.conn.close()
                    except: pass
                    try: client2.conn.close()
                    except: pass
    except socket.error as e:
        print(f"Failed to start server (bind/listen): {e}")
    finally:
        if 'ssl_server_socket' in locals() and ssl_server_socket:
            try:
                ssl_server_socket.close()
                print("SSL Server socket closed.")
            except Exception as close_e:
                print(f"ERROR: Failed to close SSL Server socket gracefully: {close_e}")

        if mongo_client:
            mongo_client.close()
            print("MongoDB client closed.")



if __name__ == "__main__":
    HOST = '0.0.0.0'
    PORT = 12345
    if len(sys.argv) > 2:
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])
    start_server(HOST, PORT)