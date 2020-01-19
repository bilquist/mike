# accounts/tests/test_views.py

from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.forms import MichaelHathewaySignUpForm, GroomsbroSignUpForm, SignUpForm



User = get_user_model()

class CreateUser():
		
	def __init__(self, *args, **kwargs):
		self.user_count = 0
		self.password = 'pe1ic4nG3org3!@!'
	
	def create(self, *args, **kwargs):
		username = kwargs.get('username', f'User{self.user_count}')
		email = kwargs.get('email', f'{username}@example.com')
		self.user_count += 1
		
		return User.objects.create_user(
			username=username,
			email=email,
			password=kwargs.get('password', self.password),
			bio = kwargs.get('password', self.password),
		)
	