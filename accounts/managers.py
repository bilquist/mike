# accounts/managers.py

from django.contrib.auth.models import UserManager
from django.core.exceptions import ValidationError



class UserManager(UserManager):
	use_in_migrations = True
	
	def _create_user(self, username, email, password, **extra_fields):
		"""Creates and saves a User with a given email, username, and password."""
		if not username:
			raise ValueError('Username is required')
		if not email:
			raise ValueError('Email is required')
		username = self.model.normalize_username(username)
		email = self.normalize_email(email)
		user = self.model(username=username, email=email, **extra_fields)
		user.set_password(password)
		user.save(using=self._db)
		return user
	
	def create_user(self, username, email, password=None, **extra_fields):
		extra_fields.setdefault('is_staff', False)
		extra_fields.setdefault('is_superuser', False)
		return self._create_user(username, email, password, **extra_fields)
	
	def create_superuser(self, username, email, password, **extra_fields):
		extra_fields.setdefault('is_staff', True)
		extra_fields.setdefault('is_superuser', True)
		
		if extra_fields.get('is_staff') is not True:
			raise ValueError('Superuser must have is_staff=True')
		if extra_fields.get('is_superuser') is not True:
			raise ValueError('Superuser must have is_superuser=True')
		
		return self._create_user(username, email, password, **extra_fields)
		
	## Overwrite original method to make this case-insensitive. We don't want case sensitive usernames.
	def get_by_natural_key(self, username):
		return self.get(**{self.model.USERNAME_FIELD + '__iexact': username})
		