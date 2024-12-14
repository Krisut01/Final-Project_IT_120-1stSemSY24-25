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
from django.contrib.auth.models import User
from cryptography.fernet import Fernet
import os
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from .models import Message
import jwt
from django.conf import settings
import requests

# Root redirect
def root_redirect(request):
    return redirect('login')  # 'login' is the name of your login URL pattern

# Dashboard
class DashboardView(TemplateView):
    template_name = 'core/dashboard.html'
    
class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

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
            # Generate JWT token after successful login
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            response = JsonResponse({'access_token': access_token})
            response.set_cookie('jwt_token', access_token)  # Store token in cookie for session
            return redirect('/dashboard')  # Redirect to the dashboard after successful login

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
class MessageListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MessageSerializer

    def get_queryset(self):
        user = self.request.user
        queryset = Message.objects.filter(sender=user) | Message.objects.filter(receiver=user)

        cipher = self.get_cipher()
        for message in queryset:
            message.content = message.decrypt_content(cipher)
        return queryset

    def get_cipher(self):
        key = os.getenv('FERNET_KEY')
        if not key:
            raise ValueError("FERNET_KEY is not set in the environment variables.")
        return Fernet(key.encode())

# Messages (API-based)
class SendMessageAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        receiver_username = request.data.get('receiver')
        content = request.data.get('content')

        if not receiver_username or not content:
            return Response({'error': 'Receiver and content are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            receiver = User.objects.get(username=receiver_username)
        except User.DoesNotExist:
            return Response({'error': 'Receiver not found'}, status=status.HTTP_404_NOT_FOUND)

        message = Message.objects.create(sender=request.user, receiver=receiver, content=content)

        message_data = {
            'sender': request.user.id,
            'receiver': receiver.id,
            'content': content,
        }

        # Ensure token is being passed and decoded correctly
        token = request.headers.get('Authorization')
        if not token:
            return Response({'error': 'Authentication token missing'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            token = token.split(' ')[1]  # Extract Bearer token
        except IndexError:
            return Response({'error': 'Invalid token format'}, status=status.HTTP_401_UNAUTHORIZED)

        # Validate the token using the JWT library (assuming you are using `rest_framework_simplejwt`)
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        app1_url = 'http://127.0.0.1:8000/api/messages/'
        app2_url = 'http://127.0.0.1:8002/api/messages/'

        try:
            response_app1 = requests.post(app1_url, json=message_data, headers=headers)
            if response_app1.status_code != 201:
                return Response({'error': 'Failed to send message to App 1'}, status=status.HTTP_400_BAD_REQUEST)
        except requests.exceptions.RequestException as e:
            return Response({'error': f'Error sending message to App 1: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            response_app2 = requests.post(app2_url, json=message_data, headers=headers)
            if response_app2.status_code != 201:
                return Response({'error': 'Failed to forward message to App 2'}, status=status.HTTP_400_BAD_REQUEST)
        except requests.exceptions.RequestException as e:
            return Response({'error': f'Error forwarding message to App 2: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'Message sent successfully'}, status=status.HTTP_201_CREATED)
