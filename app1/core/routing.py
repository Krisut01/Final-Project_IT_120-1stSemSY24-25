from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/app1/', consumers.App1Consumer.as_asgi()),
]
