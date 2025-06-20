import socket
import threading
import json
import sys
import getpass
import ssl
import os
from collections import defaultdict

# Attempt to import the real ObjectId from bson
_BSONObjectId = None
try:
    from bson.objectid import ObjectId as _BSONObjectId
except ImportError:
    print("WARNING: 'bson' module not found. Session IDs will use a fallback implementation.")
    pass  # _BSONObjectId remains None


# Our custom ObjectId class to provide a consistent interface
# regardless of whether bson.objectid.ObjectId is available.
class ObjectId:
    def __init__(self, oid_str=None):
        # Store the original string representation
        self._oid_str = str(oid_str) if oid_str is not None else "dummy_session_id"

        # Initialize internal storage for a real bson ObjectId
        self._real_oid = None
        # Flag to indicate if we are using a real bson ObjectId instance
        self._is_real_bson_oid = False

        # If the real bson ObjectId was imported, attempt to use it
        if _BSONObjectId:
            # Check if the string is a valid 24-character hex for bson's ObjectId
            if isinstance(self._oid_str, str) and len(self._oid_str) == 24 and all(
                    c in '0123456789abcdefABCDEF' for c in self._oid_str):
                try:
                    self._real_oid = _BSONObjectId(self._oid_str)
                    self._is_real_bson_oid = True
                except Exception as e:
                    # Log if real ObjectId conversion fails despite valid format
                    # This might happen for non-standard but 24-hex strings.
                    print(
                        f"WARNING: Real bson.ObjectId conversion failed for '{self._oid_str}': {e}. Using fallback ObjectId behavior.")
            else:
                # Log if string is not a valid 24-char hex for bson.ObjectId
                print(
                    f"WARNING: String '{self._oid_str}' is not a valid 24-char hex expected by bson. Using fallback ObjectId behavior.")
        # If _BSONObjectId was not imported, _is_real_bson_oid remains False.

    def __str__(self):
        """Returns the string representation, either from real ObjectId or stored string."""
        if self._is_real_bson_oid:
            return str(self._real_oid)
        return self._oid_str

    @property
    def binary(self):
        """Returns the binary representation, either from real ObjectId or mocked."""
        if self._is_real_bson_oid:
            return self._real_oid.binary
        # Mock a binary representation (e.g., bytes of the string)
        return self._oid_str.encode('utf-8')

    def hex(self):
        """Returns the hexadecimal string, either from real ObjectId or stored string."""
        if self._is_real_bson_oid:
            return self._real_oid.hex()
        return self._oid_str  # The stored string is already hex for valid ObjectIds

SERVER_CA_CERT = "/app/certs/server.crt"
APP_ENV = os.getenv('CHAT_APP_ENV', 'development').lower()
DEV_MODE = (APP_ENV == 'development')
if DEV_MODE: print(f"Client running in {APP_ENV} environment")
SERVER_CA_CERT = "/app/certs/server.crt"
SSL_DEBUG_UNSAFE = os.getenv('CHAT_SSL_DEBUG_UNSAFE', 'false').lower() == 'true'
if SSL_DEBUG_UNSAFE: print("WARNING: CHAT_SSL_DEBUG_UNSAFE is TRUE. SSL certificate verification is DISABLED.")


def send_message(conn, message_type, content):
    msg_dict = {"type": message_type, "content": content}
    try:
        data = json.dumps(msg_dict).encode('utf-8')
        conn.sendall(data + b'\n')
        return True
    except socket.error as e:
        print(f"ERROR: Failed to send message: {e}")
        return False
    except TypeError as e:
        print(f"ERROR: TypeError during JSON serialization: {e} - Msg: {msg_dict}")
        return False

def receive_message(conn):
    buffer = b''
    conn.settimeout(5)

    while True:
        try:
            chunk = conn.recv(4096)
            if not chunk:
                print("WARNING: Chunk received is None. Terminating receive_message(conn)")
                return None
            buffer += chunk
            if b'\n' in buffer:
                msg_bytes, buffer = buffer.split(b'\n', 1)
                try:
                    return json.loads(msg_bytes.decode('utf-8'))
                except json.JSONDecodeError:
                    print(f"WARNING: Malformed JSON received: {msg_bytes.decode('utf-8', errors='ignore')}")
                    continue
        except socket.timeout:
            pass
        except socket.error as e:
            print(f"ERROR: Socket error during receive: {e}")
            return None
        except Exception as e:
            print(f"ERROR: Unexpected error during receive: {e}")
            return None


client_active = True
authenticated_username = None
current_session_id = None
current_participants = []


def _handle_session_info_message(content_dict):
    """
    Helper function to process and update global variables for 'session_info' messages.
    Assumes content_dict is a dictionary containing 'sessionId', 'participants', and 'message'.
    """
    global current_session_id, current_participants, authenticated_username

    session_id_str = content_dict.get("sessionId")
    participants_list = content_dict.get("participants")
    session_message = content_dict.get("message")

    # The ObjectId class itself handles the logic of using real bson.ObjectId or mocking it.
    current_session_id = ObjectId(session_id_str) if session_id_str else None

    if participants_list:
        current_participants = participants_list
    else:
        current_participants = []

    print(f"\n[SESSION INFO]: {session_message}")
    # Display the session ID consistently (either real ObjectId or our fallback)
    print(f"  Session ID: {current_session_id if current_session_id else 'N/A'}")
    print(f"  Participants: {', '.join(current_participants)}")
    sys.stdout.flush()



def receive_from_server(sock):
    global client_active, authenticated_username, current_session_id, current_participants, current_prompt_text
    while client_active:
        response = receive_message(sock)
        if response is None:
            print("\nServer disconnected or connection lost. Exiting chat.")
            client_active = False
            break
        msg_type = response.get("type")
        content = response.get("content")

        if msg_type == "chat":
            print(f"\n{content}")
            current_prompt_text = f"{authenticated_username}> "
        elif msg_type == "info":
            print(f"\n[INFO]: {content}")
            current_prompt_text = f"{authenticated_username}> "
        elif msg_type == "auth_prompt":
            print(f"\n[SERVER]: {content}")
        elif msg_type == "auth_response":
            print(f"\n[AUTH]: {content}")
        elif msg_type == "session_info":
            if isinstance(content, dict):
                _handle_session_info_message(content)
            else:
                print(f"\n[UNKNOWN SESSION INFO FORMAT]: {content}")
                current_prompt_text = f"{authenticated_username}> "

        else:
            print(f"\n[UNKNOWN MESSAGE TYPE]: {response}")

        # After printing the server's message, re-display the client's prompt
        # and ensure it's flushed immediately.
        session_prompt_part = f" (Session:{str(current_session_id)[:6]}...)" if current_session_id else ""
        prompt_text = f"{authenticated_username}{session_prompt_part}> "
        sys.stdout.write(prompt_text)
        sys.stdout.flush()

def send_to_server(sock):
    global client_active, authenticated_username, current_prompt_text
    while client_active:
        try:
            session_prompt_part = f" (Session:{str(current_session_id)[:6]}...)" if current_session_id else ""
            prompt_text = f"{authenticated_username}{session_prompt_part}> "

            # Explicitly write and flush the prompt
            sys.stdout.write(prompt_text)
            sys.stdout.flush()
            user_input = input().strip()  # Call input with empty string
            if user_input.lower() == "!q":
                client_active = False
                break
            if not send_message(sock, "chat", user_input):
                print("failed to send message. Exiting chat.")
                client_active = False
                break
        except EOFError:
            print("\nEOF received. Exiting chat.")
            client_active = False
            break
        except Exception as e:
            print(f"ERROR: Error reading input or sending: {e}")
            client_active = False
            break

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError as e:
        print(f"WARNING: Socket shutdown failed: {e}")
        sock.close()

def authenticate_client(client_socket):
    global authenticated_username
    while True:
        # Prompt for choice first, then username/password
        choice_prompt_msg = "Do you want to (L)ogin or (R)egister? [L/R]: "

        # Explicitly write and flush the prompt for the choice
        sys.stdout.write(choice_prompt_msg)
        sys.stdout.flush()

        choice = input().strip().lower()  # Call input with empty string

        if choice not in ['l', 'r']:
            print("Invalid choice. Please enter 'L' or 'R'.")
            continue
        action = 'login' if choice == 'l' else 'register'

        username = None
        password = None
        if action == 'login':
            print("Logging in...")
            # Explicitly write and flush the prompt for username
            sys.stdout.write("Enter username: ")
            sys.stdout.flush()
            username = input().strip()
            password = getpass.getpass(f"Enter password for ({username}): ").strip()
        elif action == 'register':
            print("Registering...")
            password_confirm = None
            while password_confirm is None or password_confirm != password:
                if password_confirm is not None and password_confirm != password:
                    print("Passwords do not match. Please try again.")
                if username is None:
                    sys.stdout.write("Enter username: ")
                    sys.stdout.flush()
                    username = input().strip()
                password = getpass.getpass(f"Enter password for ({username}): ").strip()
                password_confirm = getpass.getpass(f"Confirm password for ({username}): ").strip()

        if not send_message(client_socket, "auth_request", {"action": action, "username": username, "password": password}):
            print("Failed to send authentication request. Exiting.")
            return False

        auth_response = receive_message(client_socket)
        if auth_response is None:
            print("Server disconnected or connection lost. Exiting chat.")
            return False

        if auth_response.get('type') == 'auth_response':
            print(f"[AUTH]: {auth_response.get('content').lower()}")
            if "successful" in auth_response.get('content').lower():
                authenticated_username = username
                return True
            else:
                print("Authentication failed. Please try again.")
        else:
            print(f"Unexpected response during authentication: {auth_response}")



def start_client(host, port):
    global client_active, current_session_id, current_participants
    global DEV_MODE, SSL_DEBUG_UNSAFE

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if SSL_DEBUG_UNSAFE:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        print("SSL: WARNING! CERTIFICATE VERIFICATION IS COMPLETELY DISABLED (DEBUG MODE).")
    elif DEV_MODE:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_OPTIONAL
        print("SSL: Hostname verification DISABLED (DEV_MODE is ON). Certificate verification OPTIONAL.")
    else:
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        print("SSL: Hostname verification ENABLED (DEV_MODE is OFF). Certificate verification REQUIRED.")

    if ssl_context.verify_mode != ssl.CERT_NONE:
        print(f"DEBUG: Attempting to load client CA certificate from: {SERVER_CA_CERT}")
        try:
            ssl_context.load_verify_locations(SERVER_CA_CERT)  # Load the server's public certificate as trusted CA
            print("DEBUG: Client CA certificate loaded successfully.")
        except FileNotFoundError as e:
            print(f"ERROR: Server CA certificate file not found: {e}. Please ensure '{SERVER_CA_CERT}' exists.")
            return
        except ssl.SSLError as e:
            print(f"ERROR: SSL context loading failed for CA cert: {e}. Check certificate integrity or format.")
            return
        except Exception as e:
            print(f"ERROR: Unexpected error loading CA certificate: {e}")
            return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(0.5)

    ssl_sock = None

    try:
        print(f"Attempting to connect to chat server at {host}:{port} with SSL/TLS...")

        # --- DEBUG: Resolve hostname from client perspective
        try:
            resolved_ip = socket.gethostbyname(host)
            print(f"DEBUG: Client resolved `{host}` to IP: {resolved_ip}")
        except socket.gaierror:
            print(f"ERROR: Client could not resolve hostname '{host}': {e}. Check DNS/network configuration.")
            return

        ssl_sock = ssl_context.wrap_socket(client_socket, server_hostname=host)

        ssl_sock.connect((host, port))
        print("Connected to chat server with SSL/TLS! Type '!q to quit.")

        # --- DEBUG: Inspect server certificate ---
        try:
            peer_cert = ssl_sock.getpeercert()
            if peer_cert:
                print("DEBUG: Server Certificate Details:")
                cert_subject = defaultdict(lambda: 'N/A')
                for item in peer_cert.get('subject', []):
                    for k, v in item:
                        cert_subject[k] = v
                print(f"  Common Name (CN): {cert_subject.get('commonName', 'N/A')}")

                san_list = []
                for ext in peer_cert.get('subjectAltName', []):
                    san_list.append(f"{ext[0]}={ext[1]}")
                if san_list:
                    print(f"  Subject Alt Names (SAN): {', '.join(san_list)}")
                else:
                    print(f"  Subject Alt Names (SAN): None")
            else:
                print(f"DEBUG: No peer certificate found after connection.")
        except ssl.SSLError as e:
            print(f"ERROR: Could not get peer certificate details: {e}")
        # --- END DEBUG SECTION ---

        auth_prompt_message = receive_message(ssl_sock)
        if auth_prompt_message is None:
            print("Failed to receive auth prompt. Exiting chat.")
            client_active = False
            ssl_sock.close()
            return
        print(f"[SERVER]: {auth_prompt_message.get('content')}")

        if not authenticate_client(ssl_sock):
            print("Authentication failed. Client will not proceed to chat.")
            client_active = False
            ssl_sock.close()
            return

        print(f"Welcome, {authenticated_username}! Type '!q' to quit.")
        print("Waiting for chat session to start...")

        initial_session_info_received = False
        while client_active and not initial_session_info_received:
            response = receive_message(ssl_sock)
            if response is None:
                print("Server disconnected while waiting for session info.")
                client_active = False
                break
            if response.get('type') == 'session_info':
                content = response.get('content')
                if isinstance(content, dict):
                   _handle_session_info_message(content)
                   initial_session_info_received = True
                else:
                    print(f"\n[UNKNOWN SESSION INFO FORMAT]: {content}")
                    sys.stdout.write(f"{authenticated_username}> ")
                    sys.stdout.flush()
                initial_session_info_received = True
            elif response.get('type') == 'info':
                print(f"\n[INFO]: {response.get('content')}")
                sys.stdout.write(f"{authenticated_username}> ")
                sys.stdout.flush()
            else:
                print(f"\n[UNEXPECTED MESSAGE BEFORE SESSION]: {response}")
                sys.stdout.write(f"{authenticated_username}> ")
                sys.stdout.flush()
        if not client_active:
            ssl_sock.close()
            return

        receive_thread = threading.Thread(target=receive_from_server, args=(ssl_sock,), daemon=True)
        receive_thread.start()

        send_to_server(ssl_sock)

        if receive_thread.is_alive():
            receive_thread.join(timeout=1)

    except ConnectionRefusedError:
        print("Connection refused. Is the chat server running and accessible?")
    except ssl.SSLError as e:
        print(f"SSL ERROR: {e}. Check server certificate and try again.")
    except socket.timeout:
        print("Connection timed out. No data received from server or connection attempt took too long.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception as close_e:
                print(f"Error during SSL socket close: {close_e}")
        elif client_socket:
            client_socket.close()
        print("Client finished.")

if __name__ == "__main__":
    SERVER_HOST = 'server'
    SERVER_PORT = 12345

    if len(sys.argv) > 2:
        SERVER_HOST = sys.argv[1]
        SERVER_PORT = int(sys.argv[2])

    start_client(SERVER_HOST, SERVER_PORT)