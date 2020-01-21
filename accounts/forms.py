# accounts/forms.py

import pathlib
from PIL import Image
from io import BytesIO
import os
from phonenumber_field.phonenumber import PhoneNumber
from phonenumbers import PhoneNumber as TruePhoneNumber, PhoneNumberFormat
import uuid
import datetime

from django import forms
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, password_validation
from django.contrib.auth.forms import (
	UserCreationForm, AuthenticationForm, UsernameField,
	PasswordResetForm, SetPasswordForm
)
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.mail import send_mail
from django.db.models import Q
from django.forms import widgets
from django.shortcuts import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _

from accounts import strings as account_strings
from accounts.choices import PHONE_NUMBER_COUNTRY_CODE_CHOICES
from accounts.models import (
	GenderChoice, verification_expiration_calculator, GroomsbroCode
)
#import accounts.static_values as static_values
from accounts.utils import send_verification_email
from core.utils import crop_image_to_square
from core.s3_utils import delete_s3_file, isfile_s3
from core.validators import FileValidator



USERNAME_REQUIRED_ERROR = 'You must create a username.'
USERNAME_LENGTH_ERROR = 'Letters, numbers, dashes, and underscores only. Username must be between 3 and 20 characters.'
USERNAME_UNIQUE_ERROR = 'That username is already taken.'

USER_MUST_ACCEPT_TOS_ERROR = 'You must accept the Terms and Conditions to sign up.'


User = get_user_model()

class MichaelHathewaySignUpForm(UserCreationForm):
	
	tos_accepted = forms.BooleanField(initial=False, required=True)
	sign_up_code = forms.CharField(max_length=128, required=True)
	field_order = ['username', 'email', 'password1', 'password2', 'sign_up_code', 'tos_accepted']
	
	class Meta:
		model = User
		fields = ('email', 'username', 'password1', 'password2', 'tos_accepted')
		labels = {
			'username': 'Username (3+ characters)',
			'sign_up_code': 'Enter your sign up code here'
		}
		error_messages = {
			'username': {
				'required': USERNAME_REQUIRED_ERROR,
				'invalid': USERNAME_LENGTH_ERROR,
				'unique': USERNAME_UNIQUE_ERROR,
			},
			'tos_accepted': {
				'required': USER_MUST_ACCEPT_TOS_ERROR,
				'invalid': USER_MUST_ACCEPT_TOS_ERROR,
			},
			'sign_up_code': {
				'required': 'Please enter the secret sign up code you were sent. Contact support if you have problems.',
				'invalid': 'Only one secret sign up code can grant you access, Master Hatheway. Contact support if you have problems.'
			},
		}
	
	def clean_username(self):
		username = self.cleaned_data.get('username')
		#if username.lower() != static_values.michael_hatheway_username.lower():
		if GroomsbroCode.objects.filter(username__iexact=username).first() is None:
			raise ValidationError('You cannot change your username. It is your fate.')
		if User.objects.filter(username__iexact=username).exists():
			raise ValidationError('Michael, you''ve already registered.')
		return username
	
	def clean_tos_accepted(self):
		tos_accepted = self.cleaned_data.get('tos_accepted')
		if not tos_accepted:
			raise ValidationError(USER_MUST_ACCEPT_TOS_ERROR)
		return tos_accepted
	
	def clean_sign_up_code(self):
		sign_up_code = self.cleaned_data.get('sign_up_code')
		#if sign_up_code != static_values.michael_hatheway_code:
		if GroomsbroCode.objects.filter(username__iexact=self.cleaned_data.get('username')).filter(
		code__iexact=sign_up_code).first() is None:
			raise ValidationError('Only one secret sign up code can grant you access, Master Hatheway. Contact support if you have problems.')
	
	def clean(self):
		cleaned_data = super(MichaelHathewaySignUpForm, self).clean()
		return cleaned_data
	
	def save(self, commit=True):
		user = super(MichaelHathewaySignUpForm, self).save(commit)
		return user
		
		
class GroomsbroCodeForm(forms.Form):
	
	code = forms.CharField(max_length=128, required=True)
	
	labels = {
		'code': 'Enter your sign up code here',
	}
	error_messages = {
		'code': {
			'required': 'Please enter the secret sign up code you were sent. Contact support if you have problems.',
			'invalid': 'Only one secret sign up code can grant you access, Master Hatheway. Contact support if you have problems.'
		},
	}
	
	def clean_code(self):
		code = self.cleaned_data.get('code')
		gbro = GroomsbroCode.objects.filter(code=code).first()
		if gbro is None:
			raise ValidationError('Invalid code. Contact support if you believe this to be an error.')
		self.username = gbro.username
		self.code = gbro.code
	
	def clean(self):
		cleaned_data = super(GroomsbroCodeForm, self).clean()
		return cleaned_data
	
	def save(self, commit=True):
		return self.username, self.code
		
		
class GroomsbroSignUpForm(UserCreationForm):
	
	tos_accepted = forms.BooleanField(initial=False, required=True)
	session_code = forms.CharField(max_length=128, required=False)
	field_order = ['username', 'email', 'password1', 'password2', 'sign_up_code', 'tos_accepted']
	
	class Meta:
		model = User
		fields = ('email', 'username', 'password1', 'password2', 'tos_accepted')
		labels = {
			'username': 'Username (3+ characters)',
			'sign_up_code': 'Enter your sign up code here'
		}
		error_messages = {
			'username': {
				'required': USERNAME_REQUIRED_ERROR,
				'invalid': USERNAME_LENGTH_ERROR,
				'unique': USERNAME_UNIQUE_ERROR,
			},
			'tos_accepted': {
				'required': USER_MUST_ACCEPT_TOS_ERROR,
				'invalid': USER_MUST_ACCEPT_TOS_ERROR,
			},
		}
	
	def clean_username(self):
		username = self.cleaned_data.get('username')
		username_check = GroomsbroCode.objects.filter(username=username).first()
		if username_check is None or username != username_check.username:
			raise ValidationError('The username is not valid.')
		if User.objects.filter(username__iexact=username).exists():
			raise ValidationError(f'{username}, you''ve already registered.')
		#if username and username == static_values.michael_hatheway_username:
		if username and username.lower() == GroomsbroCode.objects.filter(is_michael_hatheway=True).first().username.lower():
			err_msg = (
				'This username is reserved for <i>the</i> man, Michael Hatheway. '
				'Please sign up <a href="{% url \'hatheway_signup\' %}>'
				'here</a> or contact support if you believe there to be an error.'
			)
			self.add_error('username', err_msg)
		return username
	
	def clean_tos_accepted(self):
		tos_accepted = self.cleaned_data.get('tos_accepted')
		if not tos_accepted:
			raise ValidationError(USER_MUST_ACCEPT_TOS_ERROR)
		return tos_accepted
	
	def clean_session_code(self):
		session_code = self.cleaned_data.get('session_code')
		if session_code is None:
			raise ValidationError('Access code is missing.')
		elif GroomsbroCode.objects.filter(code__iexact=session_code).first() is None:
			raise ValidationError('Access code is incorrect.')
		return session_code
	
	def clean(self):
		cleaned_data = super(GroomsbroSignUpForm, self).clean()
		cleaned_username = cleaned_data.get('username')
		session_code = cleaned_data.get('session_code')
		if GroomsbroCode.objects.filter(username__iexact=cleaned_username).filter(code__iexact=session_code).first() is None:
			raise ValidationError('Username does not match access code generated username.')
		return cleaned_data
	
	def save(self, commit=True):
		user = super(GroomsbroSignUpForm, self).save(commit)
		return user
		
		
class SignUpForm(UserCreationForm):
	
	tos_accepted = forms.BooleanField(initial=False, required=True)
	field_order = ['username', 'email', 'password1', 'password2', 'sign_up_code', 'tos_accepted']
	
	class Meta:
		model = User
		fields = ('email', 'username', 'password1', 'password2')
		labels = {
			'username': 'Username (3+ characters)',
			'tos_accepted': 'I am at least 18 years of age and accept the Terms and Conditions herein.',
		}
		error_messages = {
			'username': {
				'required': USERNAME_REQUIRED_ERROR,
				'invalid': USERNAME_LENGTH_ERROR,
				'unique': USERNAME_UNIQUE_ERROR,
			},
			'tos_accepted': {
				'required': USER_MUST_ACCEPT_TOS_ERROR,
				'invalid': USER_MUST_ACCEPT_TOS_ERROR,
			}
		}
	
	def clean_username(self):
		username = self.cleaned_data.get('username')
		if username and User.objects.filter(username__iexact=username).exists():
			self.add_error('username', 'A user with that username already exists.')
		if username and GroomsbroCode.objects.filter(username__iexact=username).exists():
			err_msg = (
				'This username is reserved for a groomsbro. Please sign up <a href="{% url \'gbro_code_signup\' %}>'
				'here</a> or contact support if you believe there to be an error.'
			)
			self.add_error('username', err_msg)
		#if username and username == static_values.michael_hatheway_username:
		if username and username.lower() == GroomsbroCode.objects.filter(is_michael_hatheway=True).first().username.lower():
			err_msg = (
				'This username is reserved for <i>the</i> man, Michael Hatheway. '
				'Please sign up <a href="{% url \'hatheway_signup\' %}>'
				'here</a> or contact support if you believe there to be an error.'
			)
			self.add_error('username', err_msg)
		return username
	
	def clean_tos_accepted(self):
		tos_accepted = self.cleaned_data.get('tos_accepted')
		if not tos_accepted:
			self.add_error('tos_accepted', USER_MUST_ACCEPT_TOS_ERROR)
		return tos_accepted
	
	def clean(self):
		cleaned_data = super(SignUpForm, self).clean()
		return cleaned_data
	
	def save(self, commit=True):
		user = super(SignUpForm, self).save(commit)
		return user
	
		
class LoginForm(AuthenticationForm):
	
	username = UsernameField(
		label=_("Email or Username"),
		widget=forms.TextInput(attrs={'autofocus': True}),
	)
	password = forms.CharField(
		label=_("Password"),
		strip=False,
		widget=forms.PasswordInput,
	)

	def __init__(self, request=None, *args, **kwargs):
		self.request = request
		self.user_cache = None
		super(LoginForm, self).__init__(*args, **kwargs)
		# Expand the username field past 20 characters
		self.fields['username'].max_length = 254
		self.fields['username'].widget.attrs['maxlength'] = 254
		self.fields['username'].validators[0].limit_value = 254
		
		
class ForgottenPasswordResetForm(PasswordResetForm):
	"""Inspired from django.contrib.auth.forms (mostly copied)"""
	email = forms.EmailField(label=_("Email"), max_length=255)
	
	def send_mail(self, request, email, user, uid, token):
		password_reset_link = request.build_absolute_uri(
			f'{reverse("accounts:password_reset", kwargs={"uid": uid, "token": token})}'
		)
		mail_subject = account_strings.PASSWORD_RESET_SUBJECT
		mail_body = account_strings.get_password_reset_body(user.username, password_reset_link)
		from_email = account_strings.NOTIFICATION_EMAIL
		send_mail(
			mail_subject,
			mail_body,
			from_email,
			[email]
		)
	
	def save(self, request):
		"""Generate a one-use only link for resetting a password and send it to
		the user.
		"""
		email = self.cleaned_data['email']
		user = User.objects.get(Q(email__iexact=email) & Q(is_active=True))
		uid = urlsafe_base64_encode(force_bytes(user.pk))
		token = PasswordResetTokenGenerator().make_token(user)
		self.send_mail(request, email, user, uid, token)
		
		
class ResendEmailVerificationForm(forms.Form):
	email = forms.EmailField(label=_("Email"), max_length=255)
	
	def __init__(self, user, *args, **kwargs):
		self.user = user
		super().__init__(*args, **kwargs)
	
	def save(self, commit=True):
		email = self.cleaned_data['email']
		if self.user.is_email_verified: ## Email already verified
			return account_strings.RESEND_EMAIL_VERIFICATION__EMAIL_ALREADY_VERIFIED, False
		if email != self.user.email: ## Email is changed, check to make sure nobody already owns it on another account
			if User.objects.filter(email=email).exists(): ## Email alreay reserved, return message
				return account_strings.RESEND_EMAIL_VERIFICATION__NEW_EMAIL_ALREADY_EXISTS, False
			self.user.email = email
			self.user.is_email_verified = False
		if commit:
			self.user.email_verification_sent_datetime = verification_expiration_calculator(0)
			self.user.email_verification_expiration_datetime = verification_expiration_calculator()
			self.user.email_verification_sent_count += 1
			self.user.save()
		return self.user.email, True
	
	
class AccountSettingsForm(forms.ModelForm):
	
	class Meta:
		model = User
		fields = ['username', 'email',]
		labels = {
			'username': 'Username',
			'email': 'Email',
		}
	
	def clean_username(self):
		cached_username = self.instance.username
		username = self.cleaned_data.get('username')
		if cached_username != username:
			raise ValidationError('You may not change your username.')
		return username
	
	def save(self, commit=True):
		"""Adding support to send email verification if email changed"""
		save_instance = super(AccountSettingsForm, self).save(commit)
		bool_send_email = False
		## Check for changed email
		if commit and save_instance.email != self.initial['email']:
			save_instance.is_email_verified = False
			save_instance.email_verification_sent_datetime = verification_expiration_calculator(0)
			save_instance.email_verification_expiration_datetime = verification_expiration_calculator()
			save_instance.email_verification_sent_count += 1
			save_instance.save(update_fields=[
				'is_email_verified',
				'email_verification_sent_datetime',
				'email_verification_expiration_datetime',
				'email_verification_sent_count',
			])
			bool_send_email = True
		return save_instance, bool_send_email
	
	
class AccountAvatarUploadForm(forms.ModelForm):
	"""In use"""
	class Meta:
		model = User
		fields = ['avatar']
		labels = {'avatar': 'Profile Picture'}		
	
	def clean_avatar(self, width=400, height=400, quality=90, filetype='JPEG'): #, filename='avatar.jpg'):
		avatar = self.cleaned_data.get('avatar')
		cached_file_name = self.instance.avatar.name
		new_file_name = str(uuid.uuid4()).replace("-", "") + '.jpg'
		if avatar and 'avatar' in self.changed_data:
			with Image.open(avatar.file) as image:
				image = crop_image_to_square(image)
				image.thumbnail((width, height), Image.ANTIALIAS)
				avatar.file.seek(0)
				image.save(avatar.file, format=filetype)
				avatar.name = new_file_name
				# Remove the old avatar if it exists
				try:
					## do not delete default avatar image
					if cached_file_name == User.avatar_default:
						pass
					else:
						delete_s3_file(
							file_name=cached_file_name, 
							bucket_name=User._meta.get_field('avatar').storage.bucket.name,
							location=User._meta.get_field('avatar').storage.location
						)
						#if os.path.isfile(os.path.join(settings.MEDIA_ROOT, cached_file_name)):
						#	file_to_remove = os.path.join(settings.MEDIA_ROOT, cached_file_name)
						#	os.remove(file_to_remove)
					
				except Exception as e:
					pass
		return avatar
		
	
class AccountProfileForm(forms.ModelForm):
	
	class Meta:
		model = User
		fields = ['name', 'birth_date', 'gender', 'country', 'bio', 'website',]
		labels = {
			'name': 'Name',
			'birth_date': 'Birthday',
			'gender': 'Gender',
			'country': 'Country',
			'bio': 'About Me',
			'website': 'Personal Website',
		}
		widgets = {
			'birth_date': widgets.DateInput(attrs={'type': 'date'}),
		}
		
	def save(self, commit=True):
		 return super(AccountProfileForm, self).save(commit)

		
class AccountDevicesForm(forms.ModelForm):
	phone_number_raw = forms.CharField(
		label=_('Phone Number'),
		max_length = 20,
	)
	phone_number_country_code = forms.ChoiceField(
		label=_('Country Code'),
		choices=PHONE_NUMBER_COUNTRY_CODE_CHOICES,
	)
	
	class Meta:
		model = User
		fields = ['phone_number_country_code', 'phone_number_raw']
	
	def __init__(self, *args, **kwargs):
		instance = kwargs.get('instance', None)
		if instance:
			# Make phone number without country code
			country_code = str(instance.phone_number_country_code) if instance.phone_number_country_code else ''
			#plain_number = None if not instance.phone_number else str(instance.phone_number).replace('+', '')[len(country_code):]
			plain_number = None if not instance.phone_number else instance.phone_number.format_as('E164')
			kwargs.update(initial={
				'phone_number_raw': plain_number,
				'phone_number_country_code': instance.phone_number_country_code,
			})
		super(AccountDevicesForm, self).__init__(*args, **kwargs)
		
	def clean_country_code(self):
		input = self.cleaned_data['phone_number_country_code']
		for key, value in PHONE_NUMBER_COUNTRY_CODE_CHOICES:
			if input == key:
				return input
		raise ValidationError('Input country code does not match an available option.')
	
	def clean_phone_number_raw(self):
		error_messages = {
			'non_int': ('Could not recognize phone number. Please only user numbers and these characters: '
						'-, (, ), +'),
			'general': ('Error saving phone number or format unrecognized. Please try again.'),
		}
		input = self.cleaned_data['phone_number_raw']
		input = input.replace('-', '').replace('(', '').replace(')', '').replace(' ', '').replace('+', '')
		try:
			input = int(input)
		except:
			raise ValidationError(error_messages['non_int'])
		try:
			## Make sure this can be stored as PhoneNumber object
			phone = TruePhoneNumber(
				country_code = self.cleaned_data.get('phone_number_country_code'),
				national_number = input
			)
			## Make sure this can be stored as a django PhoneNumberField
			pnf_phone = PhoneNumber.from_string('+' + str(phone.country_code) + str(phone.national_number))
			if not pnf_phone.is_valid():
				raise ValidationError(error_messages['non_int'])
		except Exception as e:
			raise ValidationError(error_messages['general'])
		return pnf_phone
	
	def save(self, commit=True):
		save_instance = super(AccountDevicesForm, self).save(commit)
		if commit:
			self.instance.phone_number = self.cleaned_data['phone_number_raw']
			save_instance.save(update_fields=['phone_number'])
		return save_instance
		
		
class ChangePasswordForm(SetPasswordForm):
	error_messages = {
		'invalid_current_password': _("Please enter the correct current password to change your password."),
		'inactive': _("this account is inactive."),
	}
	
	current_password = forms.CharField(
		label=_("Current Password"),
		widget=forms.PasswordInput,
		strip=False,
		help_text=password_validation.password_validators_help_text_html(),
	)
	
	field_order = ['current_password', 'new_password_1', 'new_password_2']
	
	def __init__(self, user, *args, **kwargs):
		self.request = kwargs.pop('request')
		super(ChangePasswordForm, self).__init__(user, *args, **kwargs)
	
	def clean_current_password(self):
		"""Adapted from AuthenticationForm"""
		current_password = self.cleaned_data.get('current_password')
		self.user_cache = authenticate(self.request, username=self.user.username, password=current_password)
		if self.user_cache is None:
			raise forms.ValidationError(self.error_messages['invalid_current_password'])
		else:
			self.confirm_login_allowed(self.user_cache)
		return current_password
	
	def confirm_login_allowed(self, user):
		"""Taken from AuthenticationForm"""
		if not user.is_active:
			raise forms.ValidationError(self.error_messages['inactive'], code='inactive')
			
		
class AccountDeactivationForm(forms.ModelForm):
	"""Inspired from django.contrib.auth.forms (mostly copied)"""

	password = forms.CharField(
		label=_("Password"),
		widget=forms.PasswordInput,
		strip=False,
		help_text=password_validation.password_validators_help_text_html(),
	)
	
	field_order = ['username', 'password',]
	
	error_messages = {
		'password': {
			'required': _("Please enter the correct password to deactivate your account."),
			'invalid': _("Please enter the correct password to deactivate your account."),
		},
	}
	
	class Meta:
		model = User
		fields = ('username',)
		labels = {
			'username': 'Username',
		}
		error_messages = {
			'username': {
				'required': USERNAME_REQUIRED_ERROR,
				'invalid': USERNAME_LENGTH_ERROR,
				'unique': USERNAME_UNIQUE_ERROR,
			},
		}
		
	def __init__(self, *args, **kwargs):
		self.request = kwargs.pop('request')
		super(AccountDeactivationForm, self).__init__(*args, **kwargs)
		
	def send_mail(self, request, user):
		mail_subject = account_strings.ACCOUNT_DEACTIVATION_SUBJECT
		mail_body = account_strings.get_account_deactivation_body(user.username)
		from_email = account_strings.NOTIFICATION_EMAIL
		send_mail(
			mail_subject,
			mail_body,
			from_email,
			[user.email]
		)
		
	def confirm_login_allowed(self, user):
		"""Taken from AuthenticationForm"""
		if not user.is_active:
			raise forms.ValidationError(self.error_messages['password']['inactive'], code='inactive')
	
	def clean_username(self):
		cached_username = self.instance.username
		username = self.cleaned_data.get('username')
		if cached_username != username:
			raise ValidationError('Username mismatch. You must type in your username to delete your account.')
		print(f'Clean username success with username {username}')
		return username
	
	def clean_password(self):
		password = self.cleaned_data.get('password')
		self.user_cache = authenticate(self.request, username=self.request.user.username, password=password)
		if self.user_cache is None:
			raise forms.ValidationError(self.error_messages['password']['invalid'])
		else:
			self.confirm_login_allowed(self.user_cache)
		print(f'Clean password success with password {password}')
		return password
			
	def save(self, commit=True):
		user = self.request.user
		user.is_active = False
		if commit:
			user.save(updated_fields=['is_active'])
			self.send_mail(self.request, user)
		return user
		