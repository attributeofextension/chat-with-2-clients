import socket
import threading
import json
import sys


class ChatSession(threading.Thread):
    def __init__(self, client1_conn, client1_addr, client2_conn, client2_addr):
        super().__init__()
        self.client1_conn = client1_conn
        self.client1_addr = client1_addr
        self.client2_conn = client2_conn
        self.client2_addr = client2_addr
        self.session_active = True
        print(f"New chat session started between {client1_addr} and {client2_addr}")

        send_message(self.client1_conn, "info", f"Connected to chat. You are chatting with {client2_addr}.")
        send_message(self.client2_conn, "info", f"Connected to chat. You are chatting with {client1_addr}.")

    def relay_messages(self, sender_conn, receiver_conn, sender_addr, receiver_addr):
        while self.session_active:
            message = receive_message(sender_conn)
            if message is None:
                print(f"Client {sender_addr} disconnected. Ending chat session for {self.client1_addr} and {self.client2_addr}.")
                send_message(receiver_conn, "info", f"Your chat partner ({sender_addr}) has disconnected. Chat session ended.")
                self.session_active = False
                break

            if message.get("type") == "chat":
                print(f"[{sender_addr}]: {message.get('content')}")
                if not send_message(receiver_conn, "chat", f"[{sender_addr[1]}]: {message.get('content')}"):
                    print(f"Failed to relay message to {receiver_addr}. Ending chat session.")
                    self.session_active = False
                    break
            else:
                print(f"WARNING: Unknown message type: '{message.get('type')}' from {sender_addr}.")

        sender_conn.close()
    def run(self):
        thread1 = threading.Thread(target=self.relay_messages, args=(self.client1_conn, self.client2_conn, self.client1_addr, self.client2_addr))
        thread2 = threading.Thread(target=self.relay_messages, args=(self.client2_conn, self.client1_conn, self.client2_addr, self.client1_addr))

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

        try:
            self.client1_conn.close()
        except socket.error:
            pass
        try:
            self.client2_conn.close()
        except socket.error:
            pass

        print(f"Chat session between {self.client1_addr} and {self.client2_addr} ended.")

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
    conn.settimeout(0.5)

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

def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(1.0)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"Chat Server listening on {host}:{port}")
        print("Waiting for clients to connect...")

        pending_client = None

        while True:
            try:
                conn, addr = server_socket.accept()
                print(f"Client connected: {addr}")

                if pending_client is None:
                    pending_client = (conn, addr)
                    send_message(conn, "info", "Waiting for another user to join the chat...")
                    print(f"Client {addr} is waiting for a partner.")
                else:
                    client1_conn, client1_addr = pending_client
                    client2_conn, client2_addr = conn, addr

                    chat_session = ChatSession(client1_conn, client1_addr, client2_conn, client2_addr)
                    chat_session.start()
                    pending_client = None
                    print(f"Paired {client1_addr} to {client2_addr}. New chat session started.")

            except socket.timeout:
                continue
            except KeyboardInterrupt:
                print("\nServer shutting down.")
                break
            except Exception as e:
                print(f"An unexpected error occurred in server: {e}")
                break
    except socket.error as error:
        print(f"Socket error: {error}")
    finally:
        server_socket.close()
        print("Server socket closed")



if __name__ == "__main__":
    HOST = '0.0.0.0'
    PORT = 12345
    if len(sys.argv) > 2:
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])
    start_server(HOST, PORT)