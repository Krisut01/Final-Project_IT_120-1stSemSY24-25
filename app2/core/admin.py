from django.contrib import admin
from .models import Message

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'timestamp', 'get_encrypted_content', 'get_decrypted_content')

    def get_encrypted_content(self, obj):
        return obj.content
    get_encrypted_content.short_description = 'Encrypted Content'

    def get_decrypted_content(self, obj):
        try:
            return obj.decrypt_content()
        except Exception as e:
            return f"Error: {str(e)}"
    get_decrypted_content.short_description = 'Decrypted Content'