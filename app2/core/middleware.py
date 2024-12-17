import os
from django.utils.deprecation import MiddlewareMixin
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

class EncryptionMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        self.get_response = get_response
        key = os.getenv('FERNET_KEY')
        if not key:
            raise ValueError("FERNET_KEY is not set in the environment variables.")
        self.cipher = Fernet(key.encode())

    def process_request(self, request):
        # Skip encryption for static file requests, root URL, login page, or dashboard page
        if request.path.startswith('/static/') or request.path == '/' or request.path == '/login/' or request.path == '/dashboard/':
            return None  # Skip encryption for static files, root, login, and dashboard pages

        # Decrypt request body for message creation or other actions that require encryption
        if request.body:
            try:
                decrypted_data = self.cipher.decrypt(request.body)
                request._body = decrypted_data
            except Exception:
                pass

    def process_response(self, request, response):
        # Skip encryption for static file requests, login page, or dashboard page
        if response.status_code == 200 and (response.content.startswith(b'<!DOCTYPE html>') or request.path == '/login/' or request.path == '/dashboard/'):
            return response  # Skip encryption for HTML content (e.g., login or dashboard page)

        # Encrypt response content for specific actions (e.g., messages)
        if response.content and request.path == '/api/send-message/':  # Adjust URL path based on where messages are sent
            try:
                encrypted_data = self.cipher.encrypt(response.content)
                response.content = encrypted_data
            except Exception:
                pass
        
        return response
