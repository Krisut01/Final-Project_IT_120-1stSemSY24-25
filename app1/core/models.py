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

    def get_fernet_key(self):
        """Retrieve the Fernet key from environment variables."""
        key = os.getenv('FERNET_KEY')
        if not key:
            raise ValueError("FERNET_KEY not found in environment variables")
        return key

    def encrypt_content(self, content):
        """Encrypt the content using the Fernet key."""
        if not content:
            raise ValueError("Content cannot be empty")
        
        try:
            key = self.get_fernet_key()
            print(f"Encrypting content with key: {key[:10]}...")  # Only print the first 10 chars for security

            cipher = Fernet(key.encode())
            encrypted = cipher.encrypt(content.encode())
            print("Content encrypted successfully")
            return encrypted.decode()

        except Exception as e:
            print(f"Encryption error: {str(e)}")
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_content(self):
        """Decrypt the content using the Fernet key."""
        if not self.content:
            return ""

        try:
            key = self.get_fernet_key()

            if self.is_encrypted:
                cipher = Fernet(key.encode())
                decrypted = cipher.decrypt(self.content.encode())
                return decrypted.decode()
            return self.content

        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise ValueError(f"Decryption failed: {str(e)}")

    def save(self, *args, **kwargs):
        """Override the save method to encrypt content before saving the message."""
        if not self.pk:  # Only encrypt on creation
            print("Encrypting new message content")
            self.content = self.encrypt_content(self.content)
        
        super().save(*args, **kwargs)
