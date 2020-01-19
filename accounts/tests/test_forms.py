# accounts/tests/forms.py

import datetime
from unittest.mock import patch, call

from django.contrib.auth import get_user_model
from django.contrib.auth.forms import (
	SetPasswordForm, PasswordResetForm
)
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from accounts import strings as account_strings
from accounts.models import GroomsbroCode
from accounts.forms import (
	MichaelHathewaySignUpForm, GroomsbroCodeForm, GroomsbroSignUpForm, SignUpForm,
	LoginForm, ResendEmailVerificationForm, AccountSettingsForm, AccountAvatarUploadForm,
	AccountProfileForm
)
#import accounts.static_values as static_values

from .base import CreateUser



User = get_user_model()

class MichaelHathewaySignUpFormTest(TestCase):
	fixtures = ['accounts/fixtures/groomsbro_codes.json',]
	
	def test_sign_up_form(self):
		form_data = {
			'email': 'test@email.com',
			'username': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().username,
			'password1': 'asfd923280',
			'password2': 'asfd923280',
			'tos_accepted': True,
			'sign_up_code': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().code,
		}
		form = MichaelHathewaySignUpForm(data=form_data)
		self.assertTrue(form.is_valid())
	
	def test_must_accept_tos(self):
		form_data = {
			'email': 'test@email.com',
			'username': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().username,
			'password1': 'asfd923280',
			'password2': 'asfd923280',
			'tos_accepted': False,
			'sign_up_code': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().code,
		}
		form = MichaelHathewaySignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
	def test_cannot_make_case_sensitive_users(self):
		form_data_1 = {
			'email': 'user1@example.com',
			'username': 'MichaelHatheway',
			'password1': 'f823fb293f823hf',
			'password2': 'f823fb293f823hf',
			'tos_accepted': True,
			'sign_up_code': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().code,
		}
		form_data_2 = {
			'email': 'user2@example.com',
			'username': 'Michaelhatheway',
			'password1': 'f823fb293f823hf',
			'password2': 'f823fb293f823hf',
			'tos_accepted': True,
			'sign_up_code': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().code,
		}
		form1 = MichaelHathewaySignUpForm(data=form_data_1)
		self.assertTrue(form1.is_valid())
		form1.save()
		self.assertEqual(User.objects.count(), 1)
		self.assertEqual(User.objects.first().username, form_data_1['username'])
		
		form2 = MichaelHathewaySignUpForm(data=form_data_2)
		self.assertFalse(form2.is_valid())
		self.assertEqual(User.objects.count(), 1)
		
	def test_must_use_preset_username(self):
		form_data_1 = {
			'email': 'user1@example.com',
			'username': 'snailboi',
			'password1': 'f823fb293f823hf',
			'password2': 'f823fb293f823hf',
			'tos_accepted': True,
			'sign_up_code': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().code,
		}
		form1 = MichaelHathewaySignUpForm(data=form_data_1)
		self.assertFalse(form1.is_valid())
		
	def test_password_cannot_be_less_than_8_characters(self):
		form_data_1 = {
			'email': 'user1@example.com',
			'username': 'MichaelHatheway',
			'password1': 'f823f',
			'password2': 'f823f',
			'tos_accepted': True,
			'sign_up_code': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().code,
		}
		form1 = MichaelHathewaySignUpForm(data=form_data_1)
		self.assertFalse(form1.is_valid())
		
	def test_requires_sign_up_code(self):
		form_data_1 = {
			'email': 'user1@example.com',
			'username': 'MichaelHatheway',
			'password1': 'f823f111',
			'password2': 'f823f111',
			'tos_accepted': True,
		}
		form1 = MichaelHathewaySignUpForm(data=form_data_1)
		self.assertFalse(form1.is_valid())
		
		form_data_2 = {
			'email': 'user1@example.com',
			'username': 'MichaelHatheway',
			'password1': 'f823f111',
			'password2': 'f823f111',
			'tos_accepted': True,
			'sign_up_code': 'cat is bacon',
		}
		form2 = MichaelHathewaySignUpForm(data=form_data_2)
		self.assertFalse(form2.is_valid())
		
		

class GroomsbroCodeFormTest(TestCase):
	fixtures = ['accounts/fixtures/groomsbro_codes.json',]
	
	def test_form_returns_username(self):
		form_data = {
			'code': 'WhyAmIAlive',
		}
		form = GroomsbroCodeForm(data=form_data)
		self.assertTrue(form.is_valid())
		username = form.save()
		self.assertEqual(username, 'Brian')
		
	def test_form_requires_code(self):
		form_data = {
			'code': None
		}
		form = GroomsbroCodeForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		
		
class GroomsbroSignUpFormTest(TestCase):
	fixtures = ['accounts/fixtures/groomsbro_codes.json',]
	
	def test_can_signup(self):
		form_data = {
			'username': 'Brian',
			'email': 'a@example.com',
			'password1': 'awefwi292',
			'password2': 'awefwi292',
			'tos_accepted': True,
			'session_username': 'Brian',
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertTrue(form.is_valid())
		form.save()
		user = User.objects.first()
		self.assertEqual(form_data['username'], user.username)
		
	def test_username_must_match_session_username(self):
		form_data = {
			'username': 'BrianTHISisATest',
			'email': 'a@example.com',
			'password1': 'awefwi292',
			'password2': 'awefwi292',
			'tos_accepted': True,
			'session_username': None,
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data = {
			'username': 'BrianTHISisATest',
			'email': 'a@example.com',
			'password1': 'awefwi292',
			'password2': 'awefwi292',
			'tos_accepted': True,
			'session_username': 'BrianTHISisATes',
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data = {
			'username': 'Joe',
			'email': 'a@example.com',
			'password1': 'awefwi292',
			'password2': 'awefwi292',
			'tos_accepted': True,
			'session_username': 'Joe',
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertTrue(form.is_valid())
		form.save()
		user = User.objects.first()
		self.assertEqual(user.username, form_data['username'])
		
	def test_user_cannot_signup_with_unverified_username(self):
		form_data = {
			'username': 'BrianTHISisATest',
			'email': 'a@example.com',
			'password1': 'awefwi292',
			'password2': 'awefwi292',
			'tos_accepted': True,
			'session_username': 'BrianTHISisATest',
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
	def test_user_cannot_signup_twice(self):
		form_data = {
			'username': 'Brian',
			'email': 'a@example.com',
			'password1': 'awefwi292',
			'password2': 'awefwi292',
			'tos_accepted': True,
			'session_username': 'Brian',
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertTrue(form.is_valid())
		form.save()
		user = User.objects.first()
		self.assertEqual(form_data['username'], user.username)
		
		form2 = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form2.is_valid())
		
	def test_user_password_must_be_8_characters(self):
		form_data = {
			'username': 'Brian',
			'email': 'a@example.com',
			'password1': 'awefwi2',
			'password2': 'awefwi2',
			'tos_accepted': True,
			'session_username': 'Brian',
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
	def test_user_must_accept_tos(self):
		form_data = {
			'username': 'Brian',
			'email': 'a@example.com',
			'password1': 'awefwi211',
			'password2': 'awefwi211',
			'tos_accepted': None,
			'session_username': 'Brian',
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data['tos_accepted'] = False
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data['tos_accepted'] = True
		form = GroomsbroSignUpForm(data=form_data)
		self.assertTrue(form.is_valid())
		
	def test_user_must_have_non_empty_fields(self):
		form_data = {
			'username': 'Brian',
			'email': None,
			'password1': 'awefwi211',
			'password2': 'awefwi211',
			'tos_accepted': True,
			'session_username': 'Brian',
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data['email'] = 'abc@xzy'
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data['email'] = 'abc@xzy123.com'
		form = GroomsbroSignUpForm(data=form_data)
		self.assertTrue(form.is_valid())
		
		form_data['username'] = None
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data['username'] = 'Brian'
		form_data['password1'] = None
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
	def test_user_cannot_sign_up_as_michael_hatheway(self):
		form_data = {
			'username': 'MichaelHatheway',
			'email': 'a@example.com',
			'password1': 'awefwi211',
			'password2': 'awefwi211',
			'tos_accepted': None,
			'session_username': 'MichaelHatheway',
		}
		form = GroomsbroSignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		
class SignUpFormTest(TestCase):
	fixtures = ['accounts/fixtures/groomsbro_codes.json',]
	
	def test_can_signup(self):
		form_data = {
			'username': 'Username',
			'email': 'a@example.com',
			'password1': 'awefwi292',
			'password2': 'awefwi292',
			'tos_accepted': True,
		}
		form = SignUpForm(data=form_data)
		self.assertTrue(form.is_valid())
		form.save()
		user = User.objects.first()
		self.assertEqual(form_data['username'], user.username)
	
	def test_cannot_sign_up_with_reserved_username(self):
		form_data = {
			'username': 'Brian',
			'email': 'a@example.com',
			'password1': 'awefwi292',
			'password2': 'awefwi292',
			'tos_accepted': True,
		}
		form = SignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data = {
			'username': 'MichaelHatheway',
			'email': 'a@example.com',
			'password1': 'awefwi292',
			'password2': 'awefwi292',
			'tos_accepted': True,
		}
		form = SignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
	def test_cannot_have_password_less_than_8_characters(self):
		form_data = {
			'username': 'Username',
			'email': 'a@example.com',
			'password1': 'awefw',
			'password2': 'awefw',
			'tos_accepted': True,
		}
		form = SignUpForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		
class LoginFormTest(TestCase):
	fixtures = ['accounts/fixtures/groomsbro_codes.json',]
	
	def test_can_login(self):
		user = CreateUser().create(**{'username': 'MichaelHatheway', 'email': 'a@example.com', 'password': 'cat1918alwq', 'bio': 'cat1918alwq'})
		form_data = {
			'username': user.username,
			'password': user.bio,
		}
		form = LoginForm(data=form_data)
		self.assertTrue(form.is_valid())
		
	def test_cannot_login_with_bad_creds(self):
		user = CreateUser().create()
		form_data = {
			'username': user.username,
			'password': user.bio,
		}
		form = LoginForm(data=form_data)
		self.assertTrue(form.is_valid())
		
		form_data['password'] = 'catmilk'
		form = LoginForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data['password'] = user.bio
		form_data['username'] = 'catmilk'
		form = LoginForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data['username'] = None
		form_data['password'] = user.bio
		form = LoginForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data['username'] = user.username
		form_data['password'] = None
		form = LoginForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		form_data['username'] = None
		form_data['password'] = None
		form = LoginForm(data=form_data)
		self.assertFalse(form.is_valid())
		
		
class ForgottenPasswordResetFormTest(TestCase):
	
	def test_password_reset_form(self):
		form_data = {'email': 'test@email.com',}
		form = PasswordResetForm(data=form_data)
		self.assertTrue(form.is_valid())
		
		
class SetPasswordFormTest(TestCase):
	
	def test_set_password_form_valid_when_initialized_with_user(self):
		user = CreateUser().create()
		password = 'new_password_K#*('
		form_data = {'new_password1': password, 'new_password2': password}
		form = SetPasswordForm(user, data=form_data)
		self.assertTrue(form.is_valid())
	
	def test_set_password_form_invalid_when_passwords_are_mismatched(self):
		user = CreateUser().create()
		password1 = '238f2nf20'
		password2 = '82vn20v823'
		form_data = {'new_password1': password1, 'new_password2': password2}
		form = SetPasswordForm(user, data=form_data)
		self.assertFalse(form.is_valid())
	
	def test_set_password_form_fails_when_not_initialized_with_user(self):
		password = '238f2f02f'
		form_data = {'new_password1': password, 'new_password2': password}
		try:
			form = SetPasswordForm(data=form_data)
			self.fail('Should not have been able to create the form')
		except:
			pass
	
	def test_saving_valid_form_updates_user_password(self):
		user = CreateUser().create()
		initial_password = user.password
		new_password = '238092nf20'
		form_data = {'new_password1': new_password, 'new_password2': new_password}
		form = SetPasswordForm(user, data=form_data)
		self.assertTrue(form.is_valid())
		form.save()
		after_form_password = user.password
		user = User.objects.get(pk=user.pk)
		after_requery_password = user.password
		self.assertNotEqual(initial_password, user.password)
		## Prove we don't need to requery user to get the updated password with user.password
		self.assertEqual(after_form_password, after_requery_password)
		
		
class ResendEmailVerificationFormTest(TestCase):
	
	def test_saving_valid_form_updates_user_email(self):
		user = CreateUser().create()
		form = ResendEmailVerificationForm(user, {'email': 'new_email@example.com'})
		self.assertTrue(form.is_valid())
		_, f_bool = form.save()
		self.assertEqual('new_email@example.com', user.email)
		self.assertTrue(f_bool)
	
	def test_cannot_input_bad_email(self):
		user = CreateUser().create()
		user_email = user.email
		bad_email = 'new_email@example'
		form = ResendEmailVerificationForm(user, {'email': bad_email})
		self.assertFalse(form.is_valid())
		self.assertEqual(user.email, user_email)
		
	def test_same_email_remains_the_same(self):
		user = CreateUser().create()
		user_email = user.email
		form = ResendEmailVerificationForm(user, {'email': user.email})
		self.assertTrue(form.is_valid())
		_, f_bool = form.save()
		self.assertEqual(user_email, user.email)
		self.assertTrue(f_bool) ## Don't have a separate false condition here since we want to send the email
	
	def test_cannot_save_form_for_already_verified_email(self):
		user = CreateUser().create()
		user.is_email_verified = True
		user.save()
		form = ResendEmailVerificationForm(user, {'email': user.email})
		self.assertTrue(form.is_valid())
		f_msg, f_bool = form.save()
		self.assertEqual(f_msg, account_strings.RESEND_EMAIL_VERIFICATION__EMAIL_ALREADY_VERIFIED)
		self.assertFalse(f_bool)
	
	def test_cannot_update_email_to_an_existing_email(self):
		user1 = CreateUser().create(**{'username': 'user1', 'email': 'user1@example.com'})
		user2 = CreateUser().create(**{'username': 'user2', 'email': 'user2@example.com'})
		form = ResendEmailVerificationForm(user1, {'email': user2.email})
		self.assertTrue(form.is_valid())
		f_msg, f_bool = form.save()
		self.assertEqual(f_msg, account_strings.RESEND_EMAIL_VERIFICATION__NEW_EMAIL_ALREADY_EXISTS)
		self.assertFalse(f_bool)
	
	def test_email_verification_datetimes_update_with_save(self):
		user = CreateUser().create()
		init_sent = user.email_verification_sent_datetime
		init_exp = user.email_verification_expiration_datetime
		form = ResendEmailVerificationForm(user, {'email': user.email})
		self.assertTrue(form.is_valid())
		_, f_bool = form.save()
		self.assertTrue(f_bool)
		self.assertNotEqual(init_sent, user.email_verification_sent_datetime)
		self.assertNotEqual(init_exp, user.email_verification_expiration_datetime)
		
		
class AccountSettingsFormTest(TestCase):
	
	def test_can_save_new_email_address_with_same_username(self):
		user = CreateUser().create()
		form_data = {
			'username': user.username,
			'email': 'new_email@example.com',
		}
		form = AccountSettingsForm(instance=user, data=form_data)
		self.assertTrue(form.is_valid())
		form.save()
		self.assertEqual(user.username, form_data['username'])
		self.assertEqual(user.email, form_data['email'])
	
	def test_cannot_change_username(self):
		user = CreateUser().create()
		form_data = {
			'username': 'new_username',
			'email': 'new_email@example.com',
		}
		form = AccountSettingsForm(instance=user, data=form_data)
		self.assertFalse(form.is_valid())
	
	def test_can_save_same_form_data(self):
		user = CreateUser().create()
		form_data = {
			'username': user.username,
			'email': user.email,
		}
		form = AccountSettingsForm(instance=user, data=form_data)
		self.assertTrue(form.is_valid())
		form.save()
		self.assertEqual(user.username, form_data['username'])
		self.assertEqual(user.email, form_data['email'])
	
	def test_new_email_triggers_email_validation_fields(self):
		user = CreateUser().create()
		user.is_email_verified = True
		user.save()
		self.assertTrue(user.is_email_verified)
		form_data = {
			'username': user.username,
			'email': 'new_email@example.com',
		}
		form = AccountSettingsForm(instance=user, data=form_data)
		self.assertTrue(form.is_valid())
		form.save()
		self.assertEqual(user.email, form_data['email'])
		self.assertFalse(user.is_email_verified)
		self.assertEqual(user.email_verification_sent_count, 2)
	
	def test_same_email_does_not_trigger_email_validation(self):
		user = CreateUser().create()
		user.is_email_verified = True
		user.save()
		self.assertTrue(user.is_email_verified)
		form_data = {
			'username': user.username,
			'email': user.email,
		}
		form = AccountSettingsForm(instance=user, data=form_data)
		self.assertTrue(form.is_valid())
		form.save()
		self.assertEqual(user.email, form_data['email'])
		self.assertTrue(user.is_email_verified)
		self.assertEqual(user.email_verification_sent_count, 1)
		
		

