from django.db import models
from django.contrib.auth.models import User

class Message(models.Model):
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    content = models.TextField()  # Store encrypted content here
    timestamp = models.DateTimeField(auto_now_add=True)

    def encrypt_content(self, cipher):
        """Encrypt the content before storing it."""
        encrypted_content = cipher.encrypt(self.content.encode())
        self.content = encrypted_content.decode()

    def decrypt_content(self, cipher):
        """Decrypt the content before displaying it."""
        if self.content:
            decrypted_content = cipher.decrypt(self.content.encode())
            return decrypted_content.decode()
        return self.content

    def save(self, *args, **kwargs):
        if not self.pk:  # Encrypt only on creation
            key = os.getenv('FERNET_KEY')
            if not key:
                raise ValueError("FERNET_KEY is not set in the environment variables.")
            cipher = Fernet(key.encode())
            self.encrypt_content(cipher)
        super().save(*args, **kwargs)


    def __str__(self):
        return f"{self.sender.username} to {self.receiver.username}: {self.content[:50]}"
