import json
import time
from datetime import datetime

def format_message(sender, content, msg_type="chat"):
    return {
        "type": msg_type,
        "sender": sender,
        "content": content,
        "timestamp": datetime.now().isoformat()
    }

def serialize_message(message_dict):
    return json.dumps(message_dict)

def deserialize_message(message_json):
    try:
        return json.loads(message_json)
    except json.JSONDecodeError:
        return None

def log_event(event_type, details, client_addr=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_info = f" [{client_addr}]" if client_addr else ""
    log_entry = f"[{timestamp}] {event_type}{client_info}: {details}"
    return log_entry

def validate_message(message_dict):
    required_fields = ["type", "sender", "content", "timestamp"]
    return all(field in message_dict for field in required_fields)

def get_color_for_sender(sender):
    colors = ["\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m"]
    hash_value = hash(sender) % len(colors)
    return colors[hash_value]

def reset_color():
    return "\033[0m"
