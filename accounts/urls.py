# accounts/urls.py

"""titan URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from accounts import views



app_name = 'accounts'

urlpatterns = [
	## Account utility
	path('verify/email/confirm/', views.VerifyEmailView.as_view(), name='verify_email'),
	path('verify/email/confirm/uid/<str:uid>/token/<str:token>/', views.VerifyEmailView.as_view(), name='verify_email'),
	path('verify/email/resend/', views.ResendEmailVerificationView.as_view(), name='resend_email_verification'),
	path('password/reset/forgot/', views.ForgottenPasswordResetView.as_view(), name='forgot_password'),
	path('password/reset/confirm/', views.PasswordResetView.as_view(), name='password_reset'),
	path('password/reset/confirm/uid/<str:uid>/token/<str:token>/', views.PasswordResetView.as_view(), name='password_reset'),
	
	## Account settings
	path('edit/', views.AccountProfileView.as_view(), name='account_profile'),
	path('edit/account_avatar_upload', views.AccountAvatarUploadView.as_view(), name='account_avatar_upload'),
	path('settings/', views.AccountSettingsView.as_view(), name='account_settings'),
	path('password/', views.AccountPasswordView.as_view(), name='account_password'),
	path('devices/', views.AccountDevicesView.as_view(), name='account_devices'),
	path('remove/', views.AccountDeactivationView.as_view(), name='account_deactivation'),
	
]
