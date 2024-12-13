from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.views.generic import TemplateView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import ListCreateAPIView, ListAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Message
from .serializers import MessageSerializer, UserSerializer
from django.contrib.auth.models import User  # Correct import

# Root redirect
def root_redirect(request):
    return redirect('login')

# Dashboard
class DashboardView(TemplateView):
    template_name = 'core/dashboard.html'

# Registration (Form-based)
class RegisterFormView(View):
    def get(self, request):
        return render(request, 'core/register.html')

    def post(self, request):
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists'}, status=400)

        User.objects.create_user(username=username, email=email, password=password)
        return redirect('login')

# Registration (API-based)
class RegisterAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if User.objects.filter(username=username).exists():
            return Response({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)
        User.objects.create_user(username=username, password=password)
        return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)

# Login (Form-based)
class LoginView(View):
    def get(self, request):
        return render(request, 'core/login.html')

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('dashboard')
        return JsonResponse({'error': 'Invalid credentials'}, status=400)

# Logout
def logout_view(request):
    logout(request)
    return redirect('login')

# Messages (API-based)
class MessageView(ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Message.objects.all()
    serializer_class = MessageSerializer

    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)

# Users API
class UserListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserSerializer

# Messages API
class MessageListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MessageSerializer

    def get_queryset(self):
        user = self.request.user
        return Message.objects.filter(sender=user) | Message.objects.filter(receiver=user)

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
    LoginView
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
    path('logout/', logout_view, name='logout'),
]
