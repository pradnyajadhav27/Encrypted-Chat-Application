# 🚀 Encrypted Chat Application

A secure, real-time chat application with AES-256 encryption.

## 📁 Files

- `final_server.py` - Chat server (run this first)
- `minimized_friendly_chat.py` - Chat client (works in minimized windows)
- `crypto.py` - Encryption utilities
- `utils.py` - Message formatting utilities
- `requirements.txt` - Python dependencies

## 🚀 Quick Start

### Step 1: Start Server
```bash
python final_server.py
```

### Step 2: Start Client
```bash
python minimized_friendly_chat.py
```

### Step 3: Connect
1. Enter your username
2. Enter encryption key: `UFjgYT+he0ee0z7540lCom192BmF+LfrQarOQhSudKs=`
3. Click "Connect"

### Step 4: Chat!
- Type messages and press Enter
- Works in minimized windows
- Supports multiple users

## 🔐 Encryption

- **Algorithm**: AES-256-CBC
- **Key**: Fixed for all users
- **Encoding**: Base64
- **Padding**: PKCS7

## 🎯 Features

✅ Real-time encrypted messaging  
✅ Multi-user support  
✅ Works in minimized windows  
✅ Auto-scroll to new messages  
✅ Clean, simple interface  
✅ Secure encryption  

## 📝 Notes

- Server runs on `localhost:5555`
- All users must use the same encryption key
- Messages are encrypted end-to-end
- Server cannot read message content
