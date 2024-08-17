
from django.contrib import admin
from django.urls import path
from nwapp.views import home,about,login_new,logout_user,create_user
from api.views import user_list_create,login_api,refresh_access_token

urlpatterns = [
    path("admin/", admin.site.urls),
    path("",home,name="home"),
    path("about",about,name="about"),
    path("login",login_new,name="login"),
    path("create_account",create_user,name="create_account"),
    path("logout",logout_user,name="logout"),





    path('api/login/', login_api, name='login_api'),
    path('api/refresh-access/', refresh_access_token, name='refresh_access_token'),
    path('users/', user_list_create, name='user-list'),
]


# handler404= "nwapp.views.pnf"
