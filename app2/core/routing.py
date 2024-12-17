from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/app2/', consumers.App2Consumer.as_asgi()),
]
