from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Message

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class MessageSerializer(serializers.ModelSerializer):
    sender = serializers.SerializerMethodField()
    receiver = serializers.SerializerMethodField()
    content = serializers.CharField(write_only=True, required=True)
    displayed_content = serializers.SerializerMethodField(method_name='get_content')

    class Meta:
        model = Message
        fields = ['id', 'sender', 'receiver', 'content', 'displayed_content', 'timestamp']

    def get_sender(self, obj):
        return obj.sender.username

    def get_receiver(self, obj):
        return obj.receiver.username

    def get_content(self, obj):
        try:
            return obj.decrypt_content()
        except Exception as e:
            print(f"Error decrypting message: {str(e)}")
            return "Error decrypting message"