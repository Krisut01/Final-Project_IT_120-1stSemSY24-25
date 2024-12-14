# URL Patterns
from django.urls import path
from .views import (
    MessageView, 
    UserListView, 
    MessageListView, 
    DashboardView, 
    RegisterFormView, 
    RegisterAPIView, 
    logout_view,
    root_redirect,
    LoginView,
    SendMessageAPIView
)

urlpatterns = [
    path('', root_redirect, name='root_redirect'),
    path('register/', RegisterFormView.as_view(), name='register_form'),
    path('api/register/', RegisterAPIView.as_view(), name='register_api'),
    path('login/', LoginView.as_view(), name='login'),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('messages/', MessageView.as_view(), name='messages'),
    path('api/users/', UserListView.as_view(), name='user-list'),
    path('api/messages/', MessageListView.as_view(), name='message-list'),
    path('api/send-message/',SendMessageAPIView.as_view(), name='send-message'),
    path('logout/', logout_view, name='logout'),
]

