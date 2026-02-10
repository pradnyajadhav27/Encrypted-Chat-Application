import socket
import threading
import json
import logging
from datetime import datetime
from crypto import AESCrypto
from utils import format_message, serialize_message, deserialize_message, validate_message

class FinalServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = []
        self.client_names = {}
        
        # Fixed key
        self.fixed_key = "UFjgYT+he0ee0z7540lCom192BmF+LfrQarOQhSudKs="
        self.crypto = AESCrypto.from_key_string(self.fixed_key)
        self.running = False
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        self.running = True
        
        print(f"FINAL ENCRYPTED CHAT SERVER")
        print(f"Server: {self.host}:{self.port}")
        print(f"Key: {self.fixed_key}")
        print("=" * 50)
        
        self.logger.info(f"Server started on {self.host}:{self.port}")
        
        try:
            while self.running:
                client_socket, addr = self.server.accept()
                self.logger.info(f"New connection from {addr}")
                
                thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            self.logger.info("Server shutting down...")
        finally:
            self.server.close()
    
    def handle_client(self, client_socket, addr):
        try:
            self.clients.append(client_socket)
            
            # Wait for join message
            data = client_socket.recv(4096)
            if not data:
                return
            
            try:
                decrypted = self.crypto.decrypt(data.decode())
                message = deserialize_message(decrypted)
                
                if message and validate_message(message) and message["type"] == "join":
                    self.client_names[client_socket] = message["sender"]
                    self.logger.info(f"Client {message['sender']} joined")
                    
                    # Send welcome
                    welcome = format_message("Server", f"Welcome {message['sender']}!", "system")
                    self._send_to_client(client_socket, welcome)
                    
                    # Broadcast join
                    join_msg = format_message("Server", f"{message['sender']} joined", "system")
                    self._broadcast_to_others(client_socket, join_msg)
                    
                    # Handle messages
                    while True:
                        data = client_socket.recv(4096)
                        if not data:
                            break
                        
                        try:
                            decrypted = self.crypto.decrypt(data.decode())
                            message = deserialize_message(decrypted)
                            
                            if message and validate_message(message):
                                if message["type"] == "chat":
                                    self.logger.info(f"Message from {message['sender']}")
                                    self._broadcast_to_others(client_socket, message)
                                elif message["type"] == "leave":
                                    break
                        except Exception as e:
                            self.logger.error(f"Message error: {e}")
                            break
                else:
                    self.logger.warning(f"Expected join message from {addr}")
                    
            except Exception as e:
                self.logger.error(f"Initial message error: {e}")
        
        except Exception as e:
            self.logger.error(f"Client error: {e}")
        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            
            if client_socket in self.client_names:
                name = self.client_names[client_socket]
                del self.client_names[client_socket]
                
                leave_msg = format_message("Server", f"{name} left", "system")
                self._broadcast_to_all(leave_msg)
            
            client_socket.close()
            self.logger.info(f"Connection closed: {addr}")
    
    def _send_to_client(self, client_socket, message_dict):
        try:
            message_json = serialize_message(message_dict)
            encrypted = self.crypto.encrypt(message_json)
            client_socket.send(encrypted.encode())
        except Exception as e:
            self.logger.error(f"Send error: {e}")
    
    def _broadcast_to_others(self, sender_socket, message_dict):
        for client in self.clients:
            if client != sender_socket:
                self._send_to_client(client, message_dict)
    
    def _broadcast_to_all(self, message_dict):
        for client in self.clients:
            self._send_to_client(client, message_dict)

if __name__ == "__main__":
    server = FinalServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer stopped")
        server.stop()
