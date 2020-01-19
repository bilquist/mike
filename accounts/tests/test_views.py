# accounts/tests/views.py

import datetime
from unittest.mock import patch, call

from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.db import transaction
from django.shortcuts import reverse
from django.test import TestCase
from django.utils import timezone
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from accounts import strings as accounts_strings
from accounts.forms import (
	MichaelHathewaySignUpForm, GroomsbroSignUpForm, SignUpForm
)
from accounts.models import GroomsbroCode
#import accounts.static_values as static_values
import accounts.strings as account_strings
from accounts.tokens import email_verification_token

from .base import CreateUser



User = get_user_model()

class MichaelHathewaySignUpTest(TestCase):
	fixtures = ['accounts/fixtures/groomsbro_codes.json']

	data = {
		'email': 'test@email.com',
		'username': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().username,
		'password1': 'asfd923280',
		'password2': 'asfd923280',
		'tos_accepted': True,
		'sign_up_code': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().code,
	}
	
	def test_sign_up_page_returns_correct_template(self):
		response = self.client.get(reverse('michael_hatheway_signup'))
		self.assertTemplateUsed(response, 'accounts/michael_hatheway_signup.html')
	
	def test_sign_up_page_uses_sign_up_form(self):
		response = self.client.get(reverse('michael_hatheway_signup'))
		self.assertIsInstance(response.context['form'], MichaelHathewaySignUpForm)
		
	@patch('accounts.utils.send_mail')
	def test_sends_mail_to_address_from_signup(self, mock_send_mail):
		response = self.client.post(reverse('michael_hatheway_signup'), data=self.data)
		self.assertEqual(mock_send_mail.called, True)
		(subject, body, from_email, to_list), kwargs = mock_send_mail.call_args
		self.assertEqual(subject, 'Verify your account')
		self.assertEqual(from_email, accounts_strings.NOTIFICATION_EMAIL)
		self.assertEqual(to_list, [self.data['email']])
		
	def test_user_is_authenticated_after_sign_up(self):
		response = self.client.post(reverse('michael_hatheway_signup'), data=self.data)
		self.assertEqual(User.objects.count(), 1)
		user = User.objects.get(username=self.data['username'])
		self.assertEqual(response.status_code, 302)
		self.assertEqual(int(self.client.session['_auth_user_id']), user.pk)
	
	def test_logged_in_user_is_redirected_when_visiting_login_page(self):
		user = CreateUser().create()
		self.client.force_login(user)
		response = self.client.get(reverse('michael_hatheway_signup'))
		self.assertEqual(response.status_code, 302)
		
	def test_successful_signup_logs_user_in(self):
		response = self.client.post(reverse('michael_hatheway_signup'), data=self.data, follow=True)
		self.assertEqual(
			int(self.client.session['_auth_user_id']),
			User.objects.get(username=self.data['username']).pk
		)
		
		
class GroomsbroSignUpTest(TestCase):
	fixtures = ['accounts/fixtures/groomsbro_codes.json',]
	code_data = {
		'code': GroomsbroCode.objects.filter(is_michael_hatheway=False).first().code,
	}
	data = {
		'email': 'test@email.com',
		'username': GroomsbroCode.objects.filter(is_michael_hatheway=False).first().username,
		'password1': 'asfd923280',
		'password2': 'asfd923280',
		'tos_accepted': True,
		'sign_up_code': GroomsbroCode.objects.filter(is_michael_hatheway=False).first().code,
	}
	
	def test_sign_up_page_returns_correct_template(self):
		response = self.client.get(reverse('groomsbro_signup'))
		self.assertTemplateUsed(response, 'accounts/groomsbro_signup.html')
	
	def test_sign_up_page_uses_sign_up_form(self):
		response = self.client.get(reverse('groomsbro_signup'))
		self.assertIsInstance(response.context['gbro_signup_form'], GroomsbroSignUpForm)
	
	@patch('accounts.utils.send_mail')
	def test_sends_mail_to_address_from_signup(self, mock_send_mail):
		response = self.client.post(reverse('gbro_code_signup'), data=self.code_data)
		response = self.client.post(reverse('groomsbro_signup'), data=self.data)
		self.assertEqual(mock_send_mail.called, True)
		(subject, body, from_email, to_list), kwargs = mock_send_mail.call_args
		self.assertEqual(subject, 'Verify your account')
		self.assertEqual(from_email, accounts_strings.NOTIFICATION_EMAIL)
		self.assertEqual(to_list, [self.data['email']])
	
	def test_user_is_authenticated_after_sign_up(self):
		response = self.client.post(reverse('gbro_code_signup'), data=self.code_data)
		response = self.client.post(reverse('groomsbro_signup'), data=self.data)
		self.assertEqual(User.objects.count(), 1)
		user = User.objects.get(username=self.data['username'])
		self.assertEqual(response.status_code, 302)
		self.assertEqual(int(self.client.session['_auth_user_id']), user.pk)
	
	def test_logged_in_user_is_redirected_when_visiting_login_page(self):
		user = CreateUser().create()
		self.client.force_login(user)
		response = self.client.get(reverse('groomsbro_signup'))
		self.assertEqual(response.status_code, 302)
	
	def test_successful_signup_logs_user_in(self):
		response = self.client.post(reverse('gbro_code_signup'), data=self.code_data)
		response = self.client.post(reverse('groomsbro_signup'), data=self.data, follow=True)
		self.assertEqual(
			int(self.client.session['_auth_user_id']),
			User.objects.get(username=self.data['username']).pk
		)
	
	
class GroomsbroCodeTest(TestCase):
	fixtures = ['accounts/fixtures/groomsbro_codes.json',]
	initial_bro = GroomsbroCode.objects.filter(is_michael_hatheway=False).first()
	code_data = {
		'code': initial_bro.code,
	}
	
	def test_form_returns_associated_username(self):
		response = self.client.post(reverse('gbro_code_signup'), data=self.code_data)
		self.assertJSONEqual(
			str(response.content, encoding='utf8'), {
			'username': self.initial_bro.username,
			'error': False,
		})
		
	def test_form_returns_errors_if_code_incorrect(self):
		response = self.client.post(reverse('gbro_code_signup'), data={'code': 'incorrect'})
		self.assertJSONEqual(
			str(response.content, encoding='utf8'), {
			'error': True,
			'errors': {'code': ['Invalid code. Contact support if you believe this to be an error.']}
		})
	# Eventually test for fragments of json & no code
	
class SignUpTest(TestCase):
	fixtures = ['accounts/fixtures/groomsbro_codes.json']
	data = {
		'email': 'test@email.com',
		'username': 'MyUsername',
		'password1': 'asfd923280',
		'password2': 'asfd923280',
		'tos_accepted': True,
	}
	
	def test_sign_up_page_returns_correct_template(self):
		response = self.client.get(reverse('signup'))
		self.assertTemplateUsed(response, 'accounts/signup.html')
	
	def test_sign_up_page_uses_sign_up_form(self):
		response = self.client.get(reverse('signup'))
		self.assertIsInstance(response.context['form'], SignUpForm)
	
	@patch('accounts.utils.send_mail')
	def test_sends_mail_to_address_from_signup(self, mock_send_mail):
		response = self.client.post(reverse('signup'), data=self.data)
		self.assertEqual(mock_send_mail.called, True)
		(subject, body, from_email, to_list), kwargs = mock_send_mail.call_args
		self.assertEqual(subject, 'Verify your account')
		self.assertEqual(from_email, accounts_strings.NOTIFICATION_EMAIL)
		self.assertEqual(to_list, [self.data['email']])
	
	def test_user_is_authenticated_after_sign_up(self):
		response = self.client.post(reverse('signup'), data=self.data)
		self.assertEqual(User.objects.count(), 1)
		user = User.objects.get(username=self.data['username'])
		self.assertEqual(response.status_code, 302)
		self.assertEqual(int(self.client.session['_auth_user_id']), user.pk)
	
	def test_logged_in_user_is_redirected_when_visiting_login_page(self):
		user = CreateUser().create()
		self.client.force_login(user)
		response = self.client.get(reverse('signup'))
		self.assertEqual(response.status_code, 302)
	
	def test_successful_signup_logs_user_in(self):
		response = self.client.post(reverse('signup'), data=self.data, follow=True)
		self.assertEqual(
			int(self.client.session['_auth_user_id']),
			User.objects.get(username=self.data['username']).pk
		)
	
	
class EmailVerificationTest(TestCase):
	
	def setUp(self):
		self.data = {
			'username': 'user1',
			'email': 'user1@example.com',
			'password1': 'asf23f2f2f2',
			'password2': 'asf23f2f2f2',
		}
		self.user = CreateUser().create()
		self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
		self.token = email_verification_token.make_token(self.user)
		
	def test_can_verify_email_address_after_signup(self):
		abs_ = reverse('accounts:verify_email', kwargs={'uid': self.uid, 'token': self.token})
		response = self.client.get(reverse('accounts:verify_email', kwargs={'uid': self.uid, 'token': self.token}), follow=True)
		self.assertContains(response, account_strings.EMAIL_VERIFICATION_SUCCESS)
		self.assertTemplateUsed(response, 'core/home.html')
		## Re-pull user to verify email is verified
		self.user = User.objects.get(pk=self.user.pk)
		self.assertTrue(self.user.is_email_verified)
		
	def test_users_with_verified_emails_are_told_they_are_already_verified(self):
		self.user.is_email_verified = True
		self.user.save()
		response = self.client.get(reverse('accounts:verify_email', kwargs={'uid': self.uid, 'token': self.token}), follow=True)
		self.assertContains(response, account_strings.EMAIL_VERIFICATION_ALREADY_VERIFIED)
		self.assertTemplateUsed(response, 'core/home.html')
		
	@patch('accounts.utils.send_mail')
	def test_expired_tokens_tell_user_a_new_email_was_sent(self, mock_send_mail):
		self.user.email_verification_expiration_datetime = \
			self.user.email_verification_expiration_datetime + timezone.timedelta(hours=-49)
		self.user.save()
		response = self.client.get(reverse('accounts:verify_email', kwargs={'uid': self.uid, 'token': self.token}), follow=True)
		self.assertEqual(mock_send_mail.called, True) ## Make sure new mail was sent
		self.assertContains(response, account_strings.EMAIL_VERIFICATION_RESENT_MESSAGE)
		self.assertTemplateUsed(response, 'core/home.html')
	
	def test_missing_uid_or_token_404s(self):
		try:
			response = self.client.get(reverse('accounts:verify_email', kwargs={'uid': self.uid}))
			self.fail('No url route provided to get here')
		except:
			pass
		try:
			response = self.client.get(reverse('accounts:verify_email', kwargs={'token': self.token}))
			self.fail('No url route provided to get here')
		except:
			pass
	
	def test_bad_uid_redirects_to_home_page(self):
		uid = 'NTA' ## decoded == '50'
		response = self.client.get(reverse('accounts:verify_email', kwargs={'uid': uid, 'token': self.token}), follow=True)
		self.assertTemplateUsed(response, 'core/home.html')
		self.assertNotContains(response, account_strings.EMAIL_VERIFICATION_SUCCESS)
		self.assertNotContains(response, account_strings.EMAIL_VERIFICATION_RESENT_MESSAGE)
		self.assertNotContains(response, account_strings.EMAIL_VERIFICATION_ALREADY_VERIFIED)
	
	def test_bad_token_redirects_to_home_page(self):
		token = self.token + '2'
		response = self.client.get(reverse('accounts:verify_email', kwargs={'uid': self.uid, 'token': token}), follow=True)
		self.assertTemplateUsed(response, 'core/home.html')
		self.assertNotContains(response, account_strings.EMAIL_VERIFICATION_SUCCESS)
		self.assertNotContains(response, account_strings.EMAIL_VERIFICATION_RESENT_MESSAGE)
		self.assertNotContains(response, account_strings.EMAIL_VERIFICATION_ALREADY_VERIFIED)		
	
	def test_user_is_logged_in_after_verifying_email(self):
		response = self.client.get(reverse('accounts:verify_email', kwargs={'uid': self.uid, 'token': self.token}), follow=True)
		self.assertEqual(response.context['user'], self.user)
	
	
class LoginTest(TestCase):
	
	def test_login_page_returns_correct_template(self):
		self.assertEqual(self.client.session.get('_auth_user_id'), None)
		response = self.client.get(reverse('login'))
		self.assertTemplateUsed(response, 'accounts/login.html')
		
	def test_login_page_uses_login_form(self):
		response = self.client.get(reverse('login'))
		self.assertIsInstance(response.context['form'], AuthenticationForm)
		
	def test_can_force_login(self):
		user = CreateUser().create()
		self.client.force_login(user)
		response = self.client.get(reverse('home'))
		self.assertEqual(response.context['user'], user)
		
	def test_can_login_via_view(self):
		user = CreateUser().create()
		response = self.client.post(reverse('login'), data={
			'username': user.username,
			'password': user.bio, # bio since user.password is encrypted in the user object
		})
		self.assertEqual(int(self.client.session['_auth_user_id']), user.pk)
		
	def test_cannot_login_with_bad_creds(self):
		user = CreateUser().create()
		response = self.client.post(reverse('login'), data={
			'username': user.username,
			'password': user.bio,
		}, follow=True)
		self.assertTemplateUsed(response, 'core/home.html')
		
		
class LogoutTest(TestCase):
	
	def test_users_can_logout(self):
		self.assertNotIn('_auth_user_id', self.client.session)
		user = CreateUser().create()
		self.client.force_login(user)
		self.assertIn('_auth_user_id', self.client.session)
		self.client.get(reverse('logout'))
		self.assertNotIn('_auth_user_id', self.client.session)
		
		
class ForgottenPasswordResetTest(TestCase):
	
	@patch('accounts.forms.send_mail')
	def test_password_reset_view_submission_does_not_send_email_to_nonexistent_user(self, mock_send_mail):
		form_data = {'email': 'test@email.com',}
		response = self.client.post(reverse('accounts:forgot_password'), data=form_data, follow=True)
		self.assertEqual(response.status_code, 200)
		self.assertTemplateUsed(response, 'accounts/forgot_password.html')
		## No email would be sent since user does not exist
		self.assertEqual(mock_send_mail.called, False) ## Make sure new mail was not sent
		self.assertContains(response, account_strings.PASSWORD_RESET_FORM_SUBMITTED_RESPONSE)
		
	@patch('accounts.forms.send_mail')
	def test_password_reset_view_submission_sends_email_to_existing_user(self, mock_send_mail):
		user = CreateUser().create()
		form_data = {'email': user.email,}
		response = self.client.post(reverse('accounts:forgot_password'), data=form_data, follow=True)
		self.assertEqual(response.status_code, 200)
		self.assertTemplateUsed(response, 'accounts/forgot_password.html')
		## Email would be sent since user exists
		self.assertEqual(mock_send_mail.called, True) ## Make sure new mail was not sent
		self.assertContains(response, account_strings.PASSWORD_RESET_FORM_SUBMITTED_RESPONSE)
		(subject, body, from_email, to_list), kwargs = mock_send_mail.call_args
		self.assertEqual(subject, account_strings.PASSWORD_RESET_SUBJECT)
		self.assertEqual(from_email, account_strings.NOTIFICATION_EMAIL)
		self.assertEqual(to_list, [user.email])
		self.assertIn('/accounts/password/reset/confirm/uid/', body)
		
	
	def test_having_multiple_users_only_returns_one_for_email_match(self):
		create_user = CreateUser()
		user1 = create_user.create()
		user2 = create_user.create()
		self.assertNotEqual(user1.username, user2.username) ## make sure users are distinct
		form_data = {'email': user1.email}
		response = self.client.post(reverse('accounts:forgot_password'), data=form_data, follow=True)
		self.assertEqual(response.status_code, 200)
		self.assertTemplateUsed(response, 'accounts/forgot_password.html')
		self.assertContains(response, account_strings.PASSWORD_RESET_FORM_SUBMITTED_RESPONSE)
		
		
class PasswordResetTest(TestCase):

	def setUp(self):
		self.data = {
			'username': 'user1',
			'email': 'user1@example.com',
			'password1': '23f82fn208',
			'password2': '23f82fn208',
		}
		self.user = CreateUser().create()
		self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
		self.token = PasswordResetTokenGenerator().make_token(self.user)
	
	def test_password_reset_form_rejects_non_parameters_if_user_not_logged_in(self):
		response = self.client.get('/accounts/password/reset/confirm/', follow=True)
		self.assertTemplateUsed(response, 'accounts/forgot_password.html')
		self.assertNotContains(response, account_strings.PASSWORD_RESET_INVALID_LINK)
	
	def test_password_reset_form_accepts_logged_in_user_with_no_params(self):
		self.client.force_login(self.user)
		response = self.client.get('/accounts/password/reset/confirm/')
		self.assertTemplateUsed(response, 'accounts/password_reset.html')
	
	def test_password_reset_form_accepts_uid_and_token_parms(self): # fix
		response = self.client.get(f'/accounts/password/reset/confirm/uid/{self.uid}/token/{self.token}/')
		self.assertTemplateUsed(response, 'accounts/password_reset.html')
	
	def test_password_reset_form_rejects_bad_uid_request(self):
		uid = 'mQ' # Follow up on this... seems uid's are not very sensitive to tampering which may cause a problem
		response = self.client.get(f'/accounts/password/reset/confirm/uid/{uid}/token/{self.token}/', follow=True)
		self.assertTemplateUsed(response, 'accounts/forgot_password.html')
		self.assertContains(response, account_strings.PASSWORD_RESET_INVALID_LINK)
	
	def test_password_reset_form_rejects_bad_token_request(self):
		token = self.token[:len(self.token)-1] + '8'
		response = self.client.get(f'/accounts/password/reset/confirm/uid/{self.uid}/token/{token}/', follow=True)
		self.assertTemplateUsed(response, 'accounts/forgot_password.html')
	
	def test_password_reset_form_redirects_logged_in_user(self):
		self.client.force_login(self.user)
		pw = '28fvn202v90'
		form_data = {'new_password1': pw, 'new_password2': pw}
		response = self.client.post('/accounts/password/reset/confirm/', data=form_data)
		self.assertEqual(response.status_code, 302)
		
	def test_password_reset_form_changes_logged_in_user_password(self):
		self.client.force_login(self.user)
		current_password = self.user.password
		pw = '298vhn20'
		form_data = {'new_password1': pw, 'new_password2': pw}
		response = self.client.post('/accounts/password/reset/confirm/', data=form_data, follow=True)
		self.assertTemplateUsed(response, 'core/home.html')
		self.user = User.objects.get(pk=self.user.pk)
		self.assertNotEqual(current_password, self.user.password)
		self.assertContains(response, account_strings.PASSWORD_RESET_SUCCESS)
		self.assertEqual(response.context['user'], self.user)
	
	def test_password_reset_form_redirects_for_non_logged_in_user(self):
		pw = '2fe89fb2e8'
		response_get = self.client.get(f'/accounts/password/reset/confirm/uid/{self.uid}/token/{self.token}/')
		form_data = {'new_password1': pw, 'new_password2': pw}
		response = self.client.post('/accounts/password/reset/confirm/', data=form_data)
		self.assertEqual(response.status_code, 302)
	
	def test_password_reset_form_resets_a_password_for_non_logged_in_user(self):
		current_password = self.user.password
		pw = '2930f20bb2'
		response_get = self.client.get(f'/accounts/password/reset/confirm/uid/{self.uid}/token/{self.token}/')
		response = self.client.post('/accounts/password/reset/confirm/', data={'new_password1': pw, 'new_password2': pw}, follow=True)
		self.assertTemplateUsed(response, 'core/home.html')
		self.assertContains(response, account_strings.PASSWORD_RESET_SUCCESS)
		self.assertContains(response, account_strings.PASSWORD_RESET_SUCCESS_LOGIN_REMINDER)
		new_password = User.objects.get(pk=self.user.pk).password
		self.assertNotEqual(current_password, new_password)
		
		
class ResendEmailVerificationTest(TestCase):
	
	def test_non_logged_in_users_get_redirected(self):
		response = self.client.get('/accounts/verify/email/resend/')
		self.assertEqual(response.status_code, 302)
		response = self.client.post('/accounts/verify/email/resend/', data={'email': 'a@b.com'})
		self.assertEqual(response.status_code, 302)
	
	def test_logged_in_user_gets_correct_template(self):
		user = CreateUser().create()
		self.client.force_login(user)
		response = self.client.get('/accounts/verify/email/resend/')
		self.assertTemplateUsed(response, 'accounts/resend_email_verification.html')
	
	def test_submitted_form_updates_user_email_address_if_value_changed(self):
		user = CreateUser().create()
		user_email = user.email
		self.client.force_login(user)
		response = self.client.post('/accounts/verify/email/resend/', data={'email': 'my_new_email@example.com'},
			follow=True)
		self.assertTemplateUsed(response, 'accounts/resend_email_verification.html')
		self.assertEqual(response.context['user'].email, 'my_new_email@example.com')
	
	@patch('accounts.utils.send_mail')
	def test_submitted_form_sends_email(self, mock_send_mail):
		user = CreateUser().create()
		self.client.force_login(user)
		response = self.client.post('/accounts/verify/email/resend/', data={'email': 'my_new_email@example.com'},
			follow=True)
		self.assertEqual(mock_send_mail.called, True) ## Make sure new mail was sent
		self.assertContains(response, account_strings.get_resend_email_verification_success(response.context['user'].email))
	
	@patch('accounts.utils.send_mail')
	def test_make_sure_changed_email_to_existing_email_does_not_send_verification_or_update_account(self, mock_send_mail):
		user1 = CreateUser().create(**{'username': 'user1', 'email': 'user1@example.com'})
		user2 = CreateUser().create(**{'username': 'user2', 'email': 'user2@example.com'})
		self.client.force_login(user1)
		response = self.client.post('/accounts/verify/email/resend/', data={'email': user2.email}, follow=True)
		self.assertEqual(mock_send_mail.called, False) ## Make sure no mail was sent
		self.assertNotContains(response, account_strings.get_resend_email_verification_success(response.context['user'].email))
		self.assertContains(response, account_strings.RESEND_EMAIL_VERIFICATION__NEW_EMAIL_ALREADY_EXISTS)
	
	def test_make_sure_already_verified_does_not_show_form(self):
		user = CreateUser().create()
		user.is_email_verified = True
		user.save()
		self.client.force_login(user)
		response = self.client.get('/accounts/verify/email/resend/')
		self.assertNotContains(response, 'action="/accounts/verify/email/resend/"')
		response = self.client.post('/accounts/verify/email/resend/', {'email': user.email}, follow=True)
		self.assertNotContains(response, 'action="/accounts/verify/email/resend/"')
	
	@patch('accounts.utils.send_mail')
	def test_email_verification_datetime_columns_reset_with_newly_resent_verification(self, mock_send_mail):
		user = CreateUser().create()
		initial_sent_datetime = user.email_verification_sent_datetime
		initial_exp_datetime = user.email_verification_expiration_datetime
		self.client.force_login(user)
		response = self.client.post('/accounts/verify/email/resend/', {'email': user.email}, follow=True)
		user = User.objects.get(pk=user.pk)
		self.assertNotEqual(initial_sent_datetime, user.email_verification_sent_datetime)
		self.assertNotEqual(initial_exp_datetime, user.email_verification_expiration_datetime)
		
		
class AccountSettingsTest(TestCase):
	
	def test_unauthorized_user_cannot_access_page(self):
		response = self.client.get(reverse('accounts:account_settings'))
		self.assertEqual(response.status_code, 302)
	
	def test_logged_in_user_can_access_template(self):
		user = CreateUser().create()
		self.client.force_login(user)
		response = self.client.get(reverse('accounts:account_settings'))
		self.assertEqual(response.status_code, 200)
		self.assertTemplateUsed(response, 'accounts/account_settings.html')
	
	@patch('accounts.utils.send_mail')
	def test_no_data_in_post_request_keeps_user_model_the_same_and_no_email(self, mock_send_mail):
		user = CreateUser().create()
		init_username = user.username
		init_email = user.email
		self.client.force_login(user)
		response = self.client.post(reverse('accounts:account_settings'))
		self.assertEqual(response.status_code, 200)
		self.assertTemplateUsed(response, 'accounts/account_settings.html')
		user = User.objects.get(pk=user.pk)
		self.assertEqual(user.username, init_username)
		self.assertEqual(user.email, init_email)
		self.assertEqual(mock_send_mail.called, False) ## Make sure no mail was sent
	
	@patch('accounts.utils.send_mail')
	#def test_only_username_update_sends_verification_email(self, mock_send_mail): # no longer allow username changes
	def test_cannot_change_username(self, mock_send_mail):
		user = CreateUser().create()
		cached_username = user.username
		self.client.force_login(user)
		response = self.client.post(
			reverse('accounts:account_settings'), 
			data={'username': 'new_username', 'email': user.email}
		)
		user = User.objects.get(pk=user.pk)
		self.assertEqual(user.username, cached_username)
		self.assertEqual(mock_send_mail.called, False) ## Make sure no mail was sent
	
	@patch('accounts.utils.send_mail')
	def test_changed_email_only_sends_verification_email(self, mock_send_mail):
		user = CreateUser().create()
		self.client.force_login(user)
		response = self.client.post(
			reverse('accounts:account_settings'), 
			data={'username': user.username, 'email': 'new@example.com'}
		)
		user = User.objects.get(pk=user.pk)
		self.assertEqual(user.email, 'new@example.com')
		self.assertEqual(mock_send_mail.called, True) ## Make sure no mail was sent
		
	@patch('accounts.utils.send_mail')
	def test_changed_email_and_username_fails_and_no_email_sent(self, mock_send_mail):
		user = CreateUser().create()
		cached_username = user.username
		cached_email = user.email
		self.client.force_login(user)
		response = self.client.post(
			reverse('accounts:account_settings'), 
			data={'username': 'fred', 'email': 'new@example.com'}
		)
		user = User.objects.get(pk=user.pk)
		self.assertEqual(user.email, cached_email)
		self.assertEqual(user.username, cached_username)
		self.assertEqual(mock_send_mail.called, False) ## Make sure no mail was sent
		
		
		