from django.db import models
from django.contrib.auth.models import User
from cryptography.fernet import Fernet
import os

class Message(models.Model):
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_encrypted = models.BooleanField(default=True)

    def encrypt_content(self, content):
        if not content:
            raise ValueError("Content cannot be empty")
            
        key = os.getenv('FERNET_KEY')
        if not key:
            raise ValueError("FERNET_KEY not found in environment variables")
            
        try:
            print(f"Encrypting content with key: {key[:10]}...")  # Only print first 10 chars for security
            if self.is_encrypted:
                cipher = Fernet(key.encode())
                encrypted = cipher.encrypt(content.encode())
                print("Content encrypted successfully")
                return encrypted.decode()
            return content
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_content(self):
        if not self.content:
            return ""
            
        key = os.getenv('FERNET_KEY')
        if not key:
            raise ValueError("FERNET_KEY not found in environment variables")
            
        try:
            if self.is_encrypted:
                cipher = Fernet(key.encode())
                decrypted = cipher.decrypt(self.content.encode())
                return decrypted.decode()
            return self.content
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise ValueError(f"Decryption failed: {str(e)}")

    def save(self, *args, **kwargs):
        if not self.pk:  # Only encrypt on creation
            print("Encrypting new message content")
            self.content = self.encrypt_content(self.content)
        super().save(*args, **kwargs)