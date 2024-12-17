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
from django.db import models  # Add this import
from .serializers import MessageSerializer, UserSerializer
from django.contrib.auth.models import User
from cryptography.fernet import Fernet
import os
from django.db import models
from django.urls import path
from . import views

import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from .models import Message
import jwt
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Message
from django.contrib.auth.models import User

# Root redirect
def root_redirect(request):
    return redirect('login')  # 'login' is the name of your login URL pattern

# Dashboard
class DashboardView(TemplateView):
    template_name = 'core/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.user.is_authenticated:
            context['username'] = self.request.user.username
        return context
    
class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            serializer = UserSerializer(user)
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )


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
            
            # Create the response with the token in both cookie and JSON
            response = JsonResponse({
                'status': 'success',
                'access_token': access_token,
                'redirect_url': '/dashboard/'
            })
            
            # Set token in cookie (httponly=False allows JavaScript access)
            response.set_cookie(
                'jwt_token', 
                access_token,
                max_age=3600,  # 1 hour
                httponly=False,  # Allow JavaScript access
                samesite='Lax'
            )
            
            return response

        return JsonResponse({
            'status': 'error',
            'message': 'Invalid credentials'
        }, status=400)

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
        app1_url = 'http://127.0.0.1:8000/api/messages/'
        
        headers = {
            'Content-Type': 'application/json',  # Ensure the correct content type
        }
        
        # Send the message to App 2
        response = requests.post(app1_url, json=message_data, headers=headers)
        
        if response.status_code == 201:
            print("Message forwarded to App 1 successfully.")
        else:
            print(f"Failed to forward message to App 1. Status code: {response.status_code}")

# Users API
class MessageListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            messages = Message.objects.filter(
                models.Q(sender=request.user) | models.Q(receiver=request.user)
            ).order_by('-timestamp')
            
            serializer = MessageSerializer(messages, many=True)
            return Response(serializer.data)  # Return JSON data
        except Exception as e:
            print(f"Error in MessageListView: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve messages'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ReceiveMessageAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        sender_id = request.data.get('sender')
        receiver_username = request.data.get('receiver')
        content = request.data.get('content')

        try:
            sender = User.objects.get(id=sender_id)
            receiver = User.objects.get(username=receiver_username)

            # Create and save the message
            message = Message(sender=sender, receiver=receiver, content=content)
            message.save()

            return Response({'message': 'Message received successfully'}, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"Error saving message: {str(e)}")
            return Response({'error': 'Failed to save message'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class SendMessageAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            key = os.getenv('FERNET_KEY')
            if not key:
                return Response(
                    {'error': 'Encryption key not found'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Process request data
            receiver_username = request.data.get('receiver')
            content = request.data.get('content')

            # Validate data
            if not receiver_username or not content:
                return Response(
                    {'error': 'Receiver and content are required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            receiver = User.objects.filter(username=receiver_username).first()
            if not receiver:
                return Response(
                    {'error': 'Receiver not found'}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            # Create and save the message
            message = Message(sender=request.user, receiver=receiver, content=content)
            message.save()

            return Response(
                {'message': 'Message sent successfully'}, 
                status=status.HTTP_201_CREATED
            )
        except Exception as e:
            print(f"Error in SendMessageAPIView: {str(e)}")
            return Response(
                {'error': 'Failed to send message'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class DeleteMessageView(APIView):
    def delete(self, request, message_id):
        try:
            message = Message.objects.get(id=message_id)
            message.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Message.DoesNotExist:
            return Response({'error': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)