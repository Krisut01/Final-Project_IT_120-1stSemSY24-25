import json
from channels.generic.websocket import AsyncWebsocketConsumer
from cryptography.fernet import Fernet
from django.conf import settings

class App2Consumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = "app2_messages"
        self.room_group_name = f"chat_{self.room_name}"

        # Join the room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave the room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        encrypted_message = data['message']

        # Decrypt the message
        cipher = Fernet(settings.FERNET_KEY.encode())
        decrypted_message = cipher.decrypt(encrypted_message.encode()).decode()

        print(f"Decrypted message received in App2: {decrypted_message}")

        # Encrypt the response message
        response_message = f"Processed in App2: {decrypted_message}"
        encrypted_response = cipher.encrypt(response_message.encode()).decode()

        # Send the response back to the WebSocket client
        await self.send(text_data=json.dumps({
            'message': encrypted_response
        }))
