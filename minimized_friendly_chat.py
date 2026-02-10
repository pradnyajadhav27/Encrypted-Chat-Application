import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import json
from datetime import datetime
from crypto import AESCrypto
from utils import format_message, serialize_message, deserialize_message, validate_message

class MinimizedFriendlyChat:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Minimized Friendly Chat")
        self.root.geometry("500x400")  # Smaller default size
        self.root.minsize(400, 300)    # Minimum size
        
        # Fixed values
        self.key = "UFjgYT+he0ee0z7540lCom192BmF+LfrQarOQhSudKs="
        
        # State
        self.socket = None
        self.crypto = None
        self.username = ""
        self.connected = False
        self.running = True
        
        self.setup_ui()
        
    def setup_ui(self):
        # Connection frame - COMPACT
        conn_frame = ttk.Frame(self.root)
        conn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(conn_frame, text="User:").pack(side=tk.LEFT, padx=2)
        self.username_entry = ttk.Entry(conn_frame, width=12)
        self.username_entry.pack(side=tk.LEFT, padx=2)
        # REMOVED: self.username_entry.insert(0, "User")
        
        ttk.Label(conn_frame, text="Key:").pack(side=tk.LEFT, padx=2)
        self.key_entry = ttk.Entry(conn_frame, width=20, show="*")
        self.key_entry.pack(side=tk.LEFT, padx=2)
        # REMOVED: self.key_entry.insert(0, self.key)
        
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.connect)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = ttk.Button(conn_frame, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=2)
        
        # Chat display - EXPANDS when minimized
        chat_frame = ttk.LabelFrame(self.root, text="Chat Messages")
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Text widget with scrollbar
        text_frame = ttk.Frame(chat_frame)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.chat_text = tk.Text(text_frame, height=10, width=60, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.chat_text.yview)
        self.chat_text.configure(yscrollcommand=scrollbar.set)
        
        # Grid layout for better resizing
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)
        
        self.chat_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Configure text colors
        self.chat_text.tag_configure("system", foreground="blue")
        self.chat_text.tag_configure("error", foreground="red")
        self.chat_text.tag_configure("message", foreground="black")
        
        # Message input - ALWAYS VISIBLE
        input_frame = ttk.LabelFrame(self.root, text="Send Message")
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Compact input layout
        msg_container = ttk.Frame(input_frame)
        msg_container.pack(fill=tk.X, padx=2, pady=2)
        
        self.message_entry = ttk.Entry(msg_container, width=40)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_btn = ttk.Button(msg_container, text="Send", command=self.send_message, state=tk.DISABLED)
        self.send_btn.pack(side=tk.RIGHT)
        
        # Status bar - COMPACT
        self.status_label = ttk.Label(self.root, text="Disconnected", relief=tk.SUNKEN)
        self.status_label.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        # Keyboard shortcuts for minimized windows
        self.root.bind('<Control-q>', lambda e: self.on_close())
        self.root.bind('<Escape>', lambda e: self.disconnect() if self.connected else None)
        
        # Focus
        self.username_entry.focus()
        
        # Proper window close handling
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def connect(self):
        username = self.username_entry.get().strip()
        key = self.key_entry.get().strip()
        
        if not username:
            messagebox.showerror("Error", "Enter username")
            return
        
        if key != self.key:
            messagebox.showerror("Error", f"Wrong key!\n\nUse: {self.key}")
            return
        
        try:
            # Connect to server
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect(("localhost", 5555))
            
            # Setup crypto
            self.crypto = AESCrypto.from_key_string(key)
            self.username = username
            self.connected = True
            
            # Send join message
            join_msg = format_message(username, "", "join")
            self.send_data(join_msg)
            
            # Start receiver thread
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
            # Update UI
            self.update_ui_connected()
            self.add_message("System", f"Connected as {username}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            self.disconnect()
    
    def disconnect(self):
        self.connected = False
        
        # Send leave message
        if self.socket and self.username:
            try:
                leave_msg = format_message(self.username, "", "leave")
                self.send_data(leave_msg)
            except:
                pass
        
        # Close socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        # Update UI
        self.update_ui_disconnected()
        self.add_message("System", "Disconnected")
    
    def send_message(self):
        if not self.connected:
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        try:
            chat_msg = format_message(self.username, message, "chat")
            if self.send_data(chat_msg):
                self.message_entry.delete(0, tk.END)
                self.add_message("You", message, "message")  # Show sent message immediately
        except Exception as e:
            self.add_message("Error", f"Send failed: {e}")
    
    def send_data(self, message_dict):
        try:
            if not self.socket or not self.connected:
                return False
            
            message_json = serialize_message(message_dict)
            encrypted = self.crypto.encrypt(message_json)
            self.socket.send(encrypted.encode())
            return True
        except Exception as e:
            self.add_message("Error", f"Send error: {e}")
            return False
    
    def receive_messages(self):
        while self.connected and self.running:
            try:
                if not self.socket:
                    break
                
                data = self.socket.recv(4096)
                if not data:
                    break
                
                decrypted = self.crypto.decrypt(data.decode())
                message_dict = deserialize_message(decrypted)
                
                if message_dict and validate_message(message_dict):
                    # Use after() to safely update GUI from thread
                    self.root.after(0, self.process_received_message, message_dict)
                
            except Exception as e:
                if self.connected:
                    self.root.after(0, self.add_message, "Error", f"Receive error: {e}")
                break
        
        if self.connected:
            self.root.after(0, self.disconnect)
    
    def process_received_message(self, message_dict):
        """Process received message in main thread"""
        if message_dict["type"] == "system":
            self.add_message("System", message_dict["content"])
        elif message_dict["type"] == "chat":
            if message_dict["sender"] != self.username:  # Don't show own messages twice
                self.add_message(message_dict["sender"], message_dict["content"], "message")
    
    def add_message(self, sender, content, tag="system"):
        """Add message to chat display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Enable text widget
        self.chat_text.config(state=tk.NORMAL)
        
        # Insert message
        self.chat_text.insert(tk.END, f"[{timestamp}] {sender}: {content}\n", tag)
        
        # Disable text widget
        self.chat_text.config(state=tk.DISABLED)
        
        # Auto-scroll to bottom - IMPORTANT for minimized windows
        self.chat_text.see(tk.END)
        
        # Update window
        self.root.update_idletasks()
    
    def update_ui_connected(self):
        self.connected = True
        self.connect_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.NORMAL)
        self.send_btn.config(state=tk.NORMAL)
        self.username_entry.config(state=tk.DISABLED)
        self.key_entry.config(state=tk.DISABLED)
        self.message_entry.focus()
        self.status_label.config(text=f"Connected as {self.username}")
    
    def update_ui_disconnected(self):
        self.connected = False
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        self.username_entry.config(state=tk.NORMAL)
        self.key_entry.config(state=tk.NORMAL)
        self.username_entry.focus()
        self.status_label.config(text="Disconnected")
    
    def on_close(self):
        """Proper window closing"""
        self.running = False
        self.disconnect()
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = MinimizedFriendlyChat()
    app.run()
