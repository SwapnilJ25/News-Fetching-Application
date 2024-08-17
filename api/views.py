from django.contrib.auth.models import User
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSerializer,TokenRefreshSerializer
import datetime
import jwt
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.shortcuts import render
from django.conf import settings
from datetime import datetime, timedelta

from django.views.decorators.csrf import csrf_exempt


def check_authorized_or_not(request):
    auth_header = request.headers.get('Authorization')
    if auth_header is None or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Token is missing or invalid'}, status=401)
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        request.user_id = payload.get('user_id')  
        return None
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token has expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)


@csrf_exempt
@api_view(['GET', 'POST'])
def user_list_create(request):
    # chk = check_authorized_or_not(request)
    # if chk is not None:
    #     return chk
    # else:
        if request.method == 'GET':
            users = User.objects.all()
            serializer = UserSerializer(users, many=True)
            return Response(serializer.data)

        elif request.method == 'POST':
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



def generate_jwt_tokens(user):
    access_token_expiry = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRY)
    access_token_payload = {
        'user_id': user.id,
        'username': user.username,
        'exp': access_token_expiry,
        'iat': datetime.utcnow()
    }
    access_token = jwt.encode(access_token_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return access_token


def generate_refresh_token(user):
    refresh_token_expiry = datetime.utcnow() + timedelta(minutes=settings.JWT_REFRESH_TOKEN_EXPIRY)
    refresh_token_payload = {
        'user_id': user.id,
        'exp': refresh_token_expiry,
        'iat': datetime.utcnow()
    }
    refresh_token = jwt.encode(refresh_token_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return refresh_token

@csrf_exempt
def login_api(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            access_token = generate_jwt_tokens(user)
            refresh_token = generate_refresh_token(user)

            return JsonResponse({
                'access_token': access_token,
                'refresh_token': refresh_token,
            }, status=200)
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)
    else:
        return render(request, "login.html")

@csrf_exempt
@api_view(['POST'])
def refresh_access_token(request):
    serializer = TokenRefreshSerializer(data=request.data)
    
    if serializer.is_valid():
        refresh_token = serializer.validated_data['refresh_token']
        
        try:
            decoded = jwt.decode(refresh_token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            
            new_access_token = jwt.encode({
                'user_id': decoded['user_id'],
                'exp': datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRY) 
            }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

            new_refresh_token = jwt.encode({
                'user_id': decoded['user_id'],
                'exp': datetime.utcnow() + timedelta(minutes=settings.JWT_REFRESH_TOKEN_EXPIRY) 
            }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
            
            return Response({
                'access_token': new_access_token,
                'refresh_token': new_refresh_token,
            }, status=status.HTTP_200_OK)
        
        except jwt.ExpiredSignatureError:
            return Response({'detail': 'Refresh token has expired.'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            return Response({'detail': 'Invalid refresh token.'}, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
