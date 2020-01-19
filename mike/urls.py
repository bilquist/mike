"""mike URL Configuration

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

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.views.generic.base import TemplateView

from accounts import views as accounts_views
from accounts import urls as accounts_urls
from core import views as core_views


urlpatterns = [
    path('admin/', admin.site.urls),
	path('', core_views.HomePageView.as_view(), name='home'),
	
	# User signup, login, logout
	path('hatheway_signup', accounts_views.MichaelHathewaySignUpView.as_view(), name='michael_hatheway_signup'),
	path('groomsbro_signup', accounts_views.GroomsbroSignUpView.as_view(), name='groomsbro_signup'),
	path('gbro_code_signup', accounts_views.GroomsbroCodeSignUpView.as_view(), name='gbro_code_signup'),
	path('signup', accounts_views.SignUpView.as_view(), name='signup'),
	
	path('login', accounts_views.LoginView.as_view(), name='login'),
	path('logout', accounts_views.LogoutView.as_view(), name='logout'),
	
	# Signed-in user accounts urls
	path('accounts/', include('accounts.urls', namespace='accounts')),
	
	# Support
	path('terms_and_conditions', core_views.HomePageView.as_view(), name='terms_and_conditions'),
]

#urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) # use for local static files
#urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) # test remove

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
