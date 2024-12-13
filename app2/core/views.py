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
from django.contrib.auth.models import User  # or from .models import User
from rest_framework.generics import ListAPIView

# Root redirect
def root_redirect(request):
    return redirect('login')  # 'login' is the name of your login URL pattern

# Dashboard
class DashboardView(View):
    def get(self, request):
        user = request.user
        messages = Message.objects.filter(sender=user) | Message.objects.filter(receiver=user)
        return render(request, 'dashboard.html', {'messages': messages})

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
        print("Rendering login page...")  # Debugging line
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
import requests

class MessageView(ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Message.objects.all()
    serializer_class = MessageSerializer

    def perform_create(self, serializer):
        # Save the message in App 1
        serializer.save(sender=self.request.user)
        
        # Forward the message to App 2
        message_data = {
            'sender': self.request.user.id,
            'receiver': serializer.validated_data['receiver'].id,
            'content': serializer.validated_data['content'],
        }

        # URL of App 2's message endpoint (running on port 8002)
        app2_url = 'http://127.0.0.1:8002/api/messages/'
        
        headers = {
            'Content-Type': 'application/json',  # Ensure the correct content type
        }
        
        # Send the message to App 2
        response = requests.post(app2_url, json=message_data, headers=headers)
        
        if response.status_code == 201:
            print("Message forwarded to App 2 successfully.")
        else:
            print(f"Failed to forward message to App 2. Status code: {response.status_code}")

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
        return Message.objects.filter(sender=user) | Message.objects.filter(receiver=user.username)
