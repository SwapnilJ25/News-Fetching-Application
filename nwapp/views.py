from django.shortcuts import render,redirect
from django.contrib.auth import  logout
from django.contrib import messages
from requests import *
import datetime, jwt
import requests
from django.conf import settings
from requests.exceptions import JSONDecodeError
from django.contrib.auth.hashers import make_password



def about(request):
    token_check = validate_token(request)
    if token_check:
        return token_check
    return render(request,"about.html")
	
def create_user(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            error_message = "Passwords do not match."
            messages.error(request, error_message)
            return render(request, 'create_account.html')

        hashed_password = make_password(password)

        api_url = 'http://127.0.0.1:8000/users/'
        create_response = requests.post(api_url, data={'username': username, 'password': hashed_password})

        if create_response.status_code == 201:
            success_message = "User created successfully."
            messages.success(request, success_message)
            return redirect('login')
        else:
            error_message = "Failed to create user. Please try again."
            messages.error(request, error_message)

    return render(request, 'create_account.html')



def home(request):
	token_check = validate_token(request)
	if token_check:
		return token_check
	try:
		a1 ="http://newsapi.org/v2/top-headlines"
		a2 ="?country=in"
		a3 ="&apiKey=caa8fced3f0f4009a13cb30523f9b0d9"
		wa = a1+a2+a3
		res = get(wa)
		data = res.json()
		info = data["articles"]
		msg = info
		return render(request,"home.html",{"msg":msg})
	except Exception as e:
		return render(request,"home.html",{"msg":str(e)})
	

def validate_token(request):
    #print("validate token")
    access_token = request.session.get('access_token')
    refresh_token = request.session.get('refresh_token')
    if not access_token:
        return redirect('logout')  

    try:
        jwt.decode(access_token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return None
    except jwt.ExpiredSignatureError:
        if refresh_token:
            #print("Token expired")
            response = requests.post(
                'http://127.0.0.1:8000/api/refresh-access/',
                data={'refresh_token': refresh_token}
            )
           # print("resp-refresh",response)
            if response.status_code == 200:
                new_access_token = response.json().get('access_token')
                new_refresh_token = response.json().get('refresh_token')
                #print("new refresh token val",new_refresh_token)
                request.session['access_token'] = new_access_token
                request.session['refresh_token'] = new_refresh_token
                try:
                    jwt.decode(new_access_token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
                    return None
                except jwt.InvalidTokenError:
                    request.session.flush()
                    return redirect('logout')
            else:
                request.session.flush()
                return redirect('logout')
        else:
            request.session.flush()
            return redirect('logout')
    except jwt.InvalidTokenError:
        request.session.flush()
        return redirect('logout')
    


def logout_user(request):
      logout(request)
      return redirect('login')
      


def login_new(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        api_url = 'http://127.0.0.1:8000/api/login/'
        response = requests.post(api_url, data={'username': username, 'password': password})

        
        if response.status_code == 200:
            try:
                data = response.json()
                #print("data", data)
                access_token = data.get('access_token')
                refresh_token = data.get('refresh_token')
                request.session['access_token'] = access_token
                request.session['refresh_token'] = refresh_token

                return redirect('home')
            except JSONDecodeError:
                messages.error(request, "Failed to parse server response.")
        else:
            try:
                error_message = response.json().get('error', 'Login failed')
            except JSONDecodeError:
                error_message = "An error occurred, and the server response could not be parsed."
            messages.error(request, error_message)  

    return render(request, 'login.html')
