# accounts/authentication.py

from django.contrib.auth import backends, get_user_model
from django.db.models import Q



class EmailUsernameAuthentication(backends.ModelBackend):
	
	def authenticate(self, request, username=None, password=None, **kwargs):
		User = get_user_model()
		
		try:
			user = User.objects.get(Q(username__iexact=username) | Q(email__iexact=username))
			if user.check_password(password):
				return user
		except User.DoesNotExist:
			User().set_password(password)