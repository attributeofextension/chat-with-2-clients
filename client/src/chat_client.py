import socket
import threading
import json
import sys
import getpass

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
    conn.settimeout(0.5)

    while True:
        try:
            chunk = conn.recv(4096)
            if not chunk:
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

def receive_from_server(sock):
    global client_active, authenticated_username, current_session_id, current_participants
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
            sys.stdout.write(f"{authenticated_username}> ")
            sys.stdout.flush()
        elif msg_type == "info":
            print(f"\n[INFO]: {content}")
            sys.stdout.write(f"{authenticated_username}> ")
            sys.stdout.flush()
        elif msg_type == "auth_prompt":
            print(f"\n[AUTH]: {content}")
        elif msg_type == "data":
            if "items" in content:
                for item in content["items"]:
                    if item["key"] == "session_id":
                        current_session_id = item["value"]
                        print(f"\n[SYSTEM]: Set session ID to {current_session_id}")
                        sys.stdout.write(f"{authenticated_username} (Session:{current_session_id}...)> ")
                        sys.stdout.flush()
        else:
            print(f"\n[UNKNOWN MESSAGE TYPE]: {response}")
            sys.stdout.write(f"{authenticated_username}> ")
            sys.stdout.flush()

def send_to_server(sock):
    global client_active, authenticated_username
    while client_active:
        try:
            prompt_text = f"{authenticated_username} (Session:{current_session_id}...)> " if current_session_id else f"{authenticated_username} (Waiting for group chat...)> "
            user_input = input(prompt_text).strip()
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
        choice = input("Would you like to (L)ogin or (R)egister? [L/R]: ").strip().lower()
        if choice not in ['l', 'r']:
            print("Invalid choice. Please enter 'L' or 'R'.")
            continue
        action = 'login' if choice == 'l' else 'register'

        username = None
        password = None
        if action == 'login':
            print("Logging in...")
            username = input("Enter username: ").strip()
            password = getpass.getpass(f"Enter password for ({username}): ").strip()
        elif action == 'register':
            print("Registering...")
            password_confirm = None
            while password_confirm is None or password_confirm != password:
                if password_confirm is not None and password_confirm != password:
                    print("Passwords do not match. Please try again.")
                if username is None:
                    username = input("Enter username: ").strip()
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
    global client_active
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(0.5)

    try:
        print(f"Attempting to connect to chat server at {host}:{port}...")
        client_socket.connect((host, port))
        print("Connected to chat server! Type '!q to quit.")
        auth_prompt_message = receive_message(client_socket)
        if auth_prompt_message is None:
            print("Failed to receive auth prompt. Exiting chat.")
            client_active = False
            client_socket.close()
            return

        print(f"[SERVER]: {auth_prompt_message.get('content')}")

        if not authenticate_client(client_socket):
            print("Authentication failed. Client will not proceed to chat.")
            client_active = False
            client_socket.close()
            return

        receive_thread = threading.Thread(target=receive_from_server, args=(client_socket,))
        receive_thread.daemon = True
        receive_thread.start()

        send_to_server(client_socket)

        if receive_thread.is_alive():
            receive_thread.join(timeout=1)
    except ConnectionRefusedError:
        print("Connection refused. Is the chat server running and accessible?")
    except socket.timeout:
        print("Connection timed out. No data received from server or connection attempt took too long.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if client_socket.fileno() != -1:
            client_socket.close()
        print("Client finished.")

if __name__ == "__main__":
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 12345

    if len(sys.argv) > 2:
        SERVER_HOST = sys.argv[1]
        SERVER_PORT = int(sys.argv[2])

    start_client(SERVER_HOST, SERVER_PORT)