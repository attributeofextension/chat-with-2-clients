import socket
import threading
import json
import sys

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
    conn.settimeout(0.1)

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

def receive_from_server(sock):
    global client_active
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
            sys.stdout.write("You: ")
            sys.stdout.flush()
        elif msg_type == "info":
            print(f"\n[INFO]: {content}")
            sys.stdout.write("You: ")
            sys.stdout.flush()
        else:
            print(f"\n[UNKNOWN MESSAGE TYPE]: {response}")
            sys.stdout.write("You: ")
            sys.stdout.flush()

def send_to_server(sock):
    global client_active
    while client_active:
        try:
            user_input = input("You: ")
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
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()

def start_client(host, port):
    global client_active
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(0.5)

    try:
        print(f"Attempting to connect to chat server at {host}:{port}...")
        client_socket.connect((host, port))
        print("Connected to chat server! Type '!q to quit.")

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