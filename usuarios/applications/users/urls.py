from django.urls import path, include
from . import views

app_name = "users_app"

urlpatterns = [
    path('register/', views.UserRegisterView.as_view(), name='user-register',),
    path('', views.LoginUser.as_view(), name='user-login',),
    path('logout/', views.LogoutView.as_view(), name='user-logout',),
    path('update/', views.UpdatePwView.as_view(), name='user-update',),
    path('user-verification/<pk>/', views.CodeVerificationView.as_view(), name='user-verification',),
    path('adm/', views.AdministrarUsuariosView.as_view(), name='user-admin',),
    path('register-adm/', views.AdminRegisterView.as_view(), name='admin-register'),
    path('admin-verification/<pk>/', views.CodeAdminVerificationView.as_view(), name='admin-verification'),
    path('request-reset-password/', views.RequestPasswordResetView.as_view(), name='request-reset-password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
    #path('password_reset/', views.PasswordResetView.as_view(), name='password_reset'),
    #path('password_reset/done/', views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    #path('reset/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    #path('reset/done/', views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
]

