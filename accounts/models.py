# accounts/models.py

from phonenumber_field.modelfields import PhoneNumberField
from enum import Enum

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.mail import send_mail
from django.core.validators import EmailValidator, MinLengthValidator, MaxLengthValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from accounts.choices import PHONE_NUMBER_COUNTRY_CODE_CHOICES, COUNTRY_CHOICES, US_STATE_CHOICES
from accounts.utils import (
	CustomUsernameValidator, username_blacklist_validator, generate_permalink_id, USZipCodeValidator
)
from accounts.managers import UserManager
from core.validators import FileValidator
#from mike.storage_backends import PublicMediaStorage




def verification_expiration_calculator(deltahours=48):
	return timezone.now() + timezone.timedelta(hours=deltahours)

def avatar_upload_to(instance, filepath):
	return 'pics/users/{user_id}/avatar/{filepath}'.format(user_id=instance.id, filepath=filepath)
	


# Classes
class GenderChoice(Enum):
	"""Subclass of Enum for gender profile choices"""
	MALE = "Male"
	FEMALE = "Female"
	F2M = "F2M"
	M2F = "M2F"
	OTHER = "Other"
	
	
class User(AbstractBaseUser, PermissionsMixin):
	"""Custom user class to be used for the Mike's Night project"""
	
	# Validators
	username_validator = UnicodeUsernameValidator()
	customer_username_validator = CustomUsernameValidator()
	email_validator = EmailValidator()
	avatar_validator = FileValidator(max_size=15*1024*1024)
	
	# Default values
	avatar_default = 'pics/users/_default/avatar/default.jpg'
	
	# Model fields
	email = models.EmailField(
		_('email'),
		unique=True,
		blank=False,
		null=False,
		validators=[email_validator]
	)
	username = models.CharField(
		_('username'),
		max_length=20,
		unique=True,
		blank=False,
		null=False,
		help_text=_('Letters, numbers, dashes, and underscores only. Username must be between 3 and 20 characters.'),
		validators=[
			username_validator,
			customer_username_validator,
			username_blacklist_validator,
			MinLengthValidator(3),
			MaxLengthValidator(20),
		],
		error_messages={
			'unique': _('A user with that username already exists.'),
			'invalid': _('Letters, numbers, dashes, and underscores only. Username must be between 3 and 20 characters.'),
		},
	)
	phone_number_country_code = models.CharField(
		_('phone number country code'),
		choices=PHONE_NUMBER_COUNTRY_CODE_CHOICES,
		null=True,
		blank=True,
		max_length=5,
	)
	phone_number = PhoneNumberField(_('phone number'), blank=True, null=True, unique=True)
	is_staff = models.BooleanField(
		_('staff status'),
		default=False,
		help_text=_('Designates whether the user can log into this admin site.'),
	)
	is_active = models.BooleanField(
		_('active'),
		default=True,
		help_text=_(
			'Designates whether this user should be treated as active. '
			'Unselect this instead of deleting accounts.'
		),
	)
	date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
	permalink_id = models.CharField(max_length=10, blank=True, null=True, unique=True)
	is_email_verified = models.BooleanField(
		_('email verified'),
		default=False,
		help_text=_(
			'Designates whether the email address is verified by a provided verification link.'
		),
	)
	email_verification_sent_datetime = models.DateTimeField(default=timezone.now)
	email_verification_expiration_datetime = models.DateTimeField(default=verification_expiration_calculator)
	email_verification_sent_count = models.IntegerField(default=1)
	
	name = models.CharField(_('name'), max_length=128, null=True, blank=True)
	birth_date = models.DateField(null=True, blank=True)
	country = models.CharField(max_length=128, null=True, blank=True)
	gender = models.CharField(
		_('gender'),
		max_length=32,
		choices=[(tag.name, tag.value) for tag in GenderChoice],
		null=True,
		blank=True
	)
	bio = models.TextField(max_length=500, null=True, blank=True)
	avatar = models.ImageField(
		upload_to=avatar_upload_to,
		max_length=255,
		null=False,
		blank=True,
		default=avatar_default,
		validators=[avatar_validator],
		#storage=PublicMediaStorage() ### bring back ***
	)
	website = models.CharField(max_length=255, null=True, blank=True)
	
	# Managers
	objects = UserManager()
	
	USERNAME_FIELD = 'username'
	REQUIRED_FIELDS = ['email',]
	
	class Meta:
		verbose_name = _('user')
		verbose_name_plural = _('users')
		
	def __str__(self):
		return self.username
		
	def save(self, *args, **kwargs):
		if not self.permalink_id:
			# Generate a permalink_id until we generate q unique one
			self.permalink_id = generate_permalink_id(10)
			while User.objects.filter(permalink_id=self.permalink_id).exists():
				self.permalink_id = generate_permalink_id(10)
		super(User, self).save()
		
	def email_user(self, subject, message, from_email=None, **kwargs):
		send_mail(subject, message, from_email, [self.email], **kwargs)
		
		
		
class GroomsbroCode(models.Model):
	
	username = models.CharField(max_length=128, null=False, blank=False, unique=True)
	code = models.CharField(max_length=128, null=False, blank=False)
	is_michael_hatheway = models.BooleanField(default=False)
	
	class Meta:
		unique_together = ('username', 'code')
		verbose_name = _('groomsbro_code')
		verbose_name_plural = _('groomsbro_codes')
		
	def __str__(self):
		return self.username + ':' + self.code
		
		
		
		