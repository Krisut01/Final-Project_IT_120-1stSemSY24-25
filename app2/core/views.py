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
from .models import Message
from .serializers import MessageSerializer, UserSerializer
from django.contrib.auth.models import User
from django.db.models import Q
import requests

from rest_framework.permissions import IsAuthenticated

# Root redirect
def root_redirect(request):
    return redirect('login')

# Dashboard View (Display messages)
class DashboardView(View):
    def get(self, request):
        user = request.user
        messages = Message.objects.filter(Q(sender=user) | Q(receiver=user))
        return render(request, 'core/dashboard.html', {'messages': messages})

# Register (Form-based)
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

# Register API (JSON-based)
class RegisterAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if User.objects.filter(username=username).exists():
            return Response({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)
        User.objects.create_user(username=username, password=password)
        return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)

# Login View
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

class MessageView(APIView):
    permission_classes = [IsAuthenticated]

    # Get the list of messages for the current user
    def get(self, request):
        user = request.user
        messages = Message.objects.filter(Q(sender=user) | Q(receiver=user))
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)

    # Create a new message
    def post(self, request):
        sender = request.user
        receiver_username = request.data.get('receiver')
        content = request.data.get('content')

        try:
            receiver = User.objects.get(username=receiver_username)
            message = Message.objects.create(sender=sender, receiver=receiver, content=content)
            serializer = MessageSerializer(message)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({"detail": "Receiver user not found."}, status=status.HTTP_404_NOT_FOUND)


# Messages List View (for user-specific messages)
class MessageListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MessageSerializer

    def get_queryset(self):
        user = self.request.user
        return Message.objects.filter(Q(sender=user) | Q(receiver=user))

