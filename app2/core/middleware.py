from django.utils.deprecation import MiddlewareMixin
from cryptography.fernet import Fernet

class EncryptMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        self.get_response = get_response
        self.cipher = Fernet(b'your-fernet-key-goes-here')  # Replace with your actual key

    def process_request(self, request):
        if request.body:
            try:
                decrypted_data = self.cipher.decrypt(request.body)
                request._body = decrypted_data
            except Exception:
                pass

    def process_response(self, request, response):
        if response.content:
            try:
                encrypted_data = self.cipher.encrypt(response.content)
                response.content = encrypted_data
            except Exception:
                pass
        return response
