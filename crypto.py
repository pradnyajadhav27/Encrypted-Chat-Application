import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AESCrypto:
    def __init__(self, key=None):
        if key is None:
            self.key = os.urandom(32)  # 256-bit key
        else:
            self.key = key
    
    def encrypt(self, plaintext):
        iv = os.urandom(16)  # 128-bit IV
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        padder = padding.PKCS7(128).padder()
        
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return base64.b64encode(iv + ciphertext).decode()
    
    def decrypt(self, ciphertext_b64):
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = ciphertext[:16]
            actual_ciphertext = ciphertext[16:]
            
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def get_key(self):
        return base64.b64encode(self.key).decode()
    
    @classmethod
    def from_key_string(cls, key_string):
        key = base64.b64decode(key_string.encode())
        return cls(key)
