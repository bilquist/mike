# accounts/views.py

import traceback
from urllib.request import Request, urlopen

from django.contrib import messages
from django.contrib.auth import (
	REDIRECT_FIELD_NAME, login as auth_login, logout as auth_logout,
	get_user_model, update_session_auth_hash,
)
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import SetPasswordForm, PasswordResetForm
from django.contrib.auth.mixins import UserPassesTestMixin, LoginRequiredMixin
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView, LoginView
from django.db.models import Q, Subquery, OuterRef
from django.http import HttpResponse, HttpResponseRedirect, Http404, JsonResponse
from django.shortcuts import redirect, render, reverse
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import is_safe_url, urlsafe_base64_encode, urlsafe_base64_decode
from django.views.generic.base import View
from django.views.generic.edit import FormView

from accounts import strings as account_strings
from accounts.forms import (
	MichaelHathewaySignUpForm, GroomsbroSignUpForm, GroomsbroCodeForm, SignUpForm,
	LoginForm, ForgottenPasswordResetForm, ResendEmailVerificationForm, AccountSettingsForm,
	AccountProfileForm, AccountDevicesForm, ChangePasswordForm, AccountDeactivationForm,
	AccountAvatarUploadForm
)
from accounts.mixins import VerifiedEmailMixin
from accounts.models import GroomsbroCode
#import accounts.static_values as static_values
from accounts.tokens import email_verification_token
from accounts.utils import send_verification_email




User = get_user_model()

class MichaelHathewaySignUpView(FormView):
	template_name = 'accounts/michael_hatheway_signup.html'
	form_class = MichaelHathewaySignUpForm
	success_url = reverse_lazy('home')

	def dispatch(self, request, *args, **kwargs):
		if request.user.is_authenticated:
			return HttpResponseRedirect('/')
		return super(MichaelHathewaySignUpView, self).dispatch(request, *args, **kwargs)
	
	def get_context_data(self, **kwargs):
		context = super(MichaelHathewaySignUpView, self).get_context_data(**kwargs)
		try:
			#user = User.objects.get(Q(username__iexact=static_values.michael_hatheway_username)).first()
			user = User.objects.get(Q(username__iexact=GroomsbroCode.objects.filter(is_michael_hatheway=True).first().username)).first()
			does_michael_exist = True
		except User.DoesNotExist:
			does_michael_exist = False
		context['does_michael_exist'] = does_michael_exist
		return context			
		
	def get(self, request, *args, **kwargs):
		#initial = {'username': static_values.michael_hatheway_username}
		initial = {'username': GroomsbroCode.objects.filter(is_michael_hatheway=True).first().username}
		form = MichaelHathewaySignUpForm(initial=initial)
		context = {'form': form}
		return render(request, self.template_name, context)
		
	def form_invalid(self, form):
		return super(MichaelHathewaySignUpView, self).form_invalid(form)
		
	def form_valid(self, form):
		user = form.save()
		send_verification_email(self.request, user)
		auth_login(self.request, user, backend='accounts.authentication.EmailUsernameAuthentication')
		return super(MichaelHathewaySignUpView, self).form_valid(form)
		
		
class GroomsbroSignUpView(View):
	template_name = 'accounts/groomsbro_signup.html'
	success_url = reverse_lazy('home')
	
	def dispatch(self, request, *args, **kwargs):
		if request.user.is_authenticated:
			return HttpResponseRedirect('/')
		return super(GroomsbroSignUpView, self).dispatch(request, *args, **kwargs)
		
	def get_success_url(self):
		"""Return the URL to redirect to after processing a valid form."""
		if not self.success_url:
			raise ImproperlyConfigured("No URL to redirect to. Provide a success_url.")
		return str(self.success_url) # success_url may be lazy
		
	def get(self, request, *args, **kwargs):
		# Check for remaining groomsbros to sign up
		gbros_remaining = GroomsbroCode.objects.extra(where=["""
			NOT EXISTS (SELECT 1 FROM {users} WHERE username={gbro_codes}.username)
			""".format(users=User._meta.db_table, gbro_codes=GroomsbroCode._meta.db_table)
		]).count()
		gbro_code_form = GroomsbroCodeForm()
		gbro_signup_form = GroomsbroSignUpForm()
		return render(request, self.template_name, context={
			'gbros_remaining': gbros_remaining,
			'gbro_code_form': gbro_code_form,
			'gbro_signup_form': gbro_signup_form,
		})
		
	def post(self, request, *args, **kwargs):
		# Validate the form
		gbro_signup_form = GroomsbroSignUpForm(request.POST.copy())
		gbro_signup_form.data['session_username'] = request.session.get('gbro_username')
		if gbro_signup_form.is_valid():
			user = gbro_signup_form.save()
			send_verification_email(self.request, user)
			auth_login(self.request, user, backend='accounts.authentication.EmailUsernameAuthentication')
			#redirect(reverse_lazy('home'))
			return HttpResponseRedirect(self.get_success_url())
		gbros_remaining = GroomsbroCode.objects.extra(where=["""
			NOT EXISTS (SELECT 1 FROM {users} WHERE username={gbro_codes}.username)
			""".format(users=User._meta.db_table, gbro_codes=GroomsbroCode._meta.db_table)
		]).count()
		gbro_code_form = GroomsbroCodeForm()
		return render(request, self.template_name, context={
			'gbros_remaining': gbros_remaining,
			'gbro_code_form': gbro_code_form,
			'gbro_signup_form': gbro_signup_form,
		})
		
		
class GroomsbroCodeSignUpView(View):
	
	def post(self, request, *args, **kwargs):
		data = dict()
		form = GroomsbroCodeForm(request.POST)
		if form.is_valid():
			data['username'], data['code'] = form.save()
			data['error'] = False
			request.session['gbro_username'] = data['username']
		else:
			data['errors'] = form._errors
			data['error'] = True
		return JsonResponse(data)
	
	
class SignUpView(FormView):
	template_name = 'accounts/signup.html'
	form_class = SignUpForm
	success_url = reverse_lazy('home')
	
	def dispatch(self, request, *args, **kwargs):
		if request.user.is_authenticated:
			return HttpResponseRedirect('/')
		return super(SignUpView, self).dispatch(request, *args, **kwargs)
		
	def form_invalid(self, form):
		return super(SignUpView, self).form_invalid(form)
		
	def form_valid(self, form):
		user = form.save()
		send_verification_email(self.request, user)
		auth_login(self.request, user, backend='accounts.authentication.EmailUsernameAuthentication')
		return super(SignUpView, self).form_valid(form)
		
		
class VerifyEmailView(View):
	template_name = 'accounts/verify_email.html'
	
	def get(self, request, *args, **kwargs):
		try:
			uidb64 = kwargs.get('uid')
			token = kwargs.get('token')
			if uidb64 is None or token is None:
				raise Http404
			uid = force_text(urlsafe_base64_decode(uidb64))
			user = User.objects.get(pk=uid)
		except (TypeError, ValueError, OverflowError, User.DoesNotExist):
			user = None
			
		if user is not None:
			if email_verification_token.check_token(user, token):
				if not user.is_email_verified:
					if timezone.now() > user.email_verification_expiration_datetime:
						## Send new verification email if expiration datetime is passed
						user.email_verification_sent_datetime = timezone.now()
						user.email_verification_expiration_datetime = \
							user.email_verification_sent_datetime + timezone.timedelta(hours=48)
						user.email_verification_sent_count = user.email_verification_sent_count + 1
						user.save(update_fields=[
							'email_verification_sent_datetime',
							'email_verification_expiration_datetime',
							'email_verification_sent_count',
						])
						send_verification_email(request, user)
						messages.success(request, account_strings.EMAIL_VERIFICATION_RESENT_MESSAGE)
					else:
						user.is_email_verified = True
						user.save(update_fields=['is_email_verified'])
						## Log user in when they verify their email for the first time
						auth_login(request, user, backend='accounts.authentication.EmailUsernameAuthentication')
						messages.success(request, account_strings.EMAIL_VERIFICATION_SUCCESS)
				else:
					messages.success(request, account_strings.EMAIL_VERIFICATION_ALREADY_VERIFIED)
			else:
				messages.error(request, account_strings.EMAIL_VERIFICATION_TOKEN_INVALID)
		return redirect('home')
		
		
class LoginView(LoginView):
	authentication_form = LoginForm
	redirect_field_name = REDIRECT_FIELD_NAME
	template_name = 'accounts/login.html'
	redirect_authenticated_user = False
	
	def dispatch(self, request, *args, **kwargs):
		if request.user.is_authenticated:
			print('user is authenticated')
			return HttpResponseRedirect(reverse_lazy('home'))
		return super(LoginView, self).dispatch(request, *args, **kwargs)
		
	def form_valid(self, form):
		auth_login(self.request, form.get_user())
		return super(LoginView, self).form_valid(form)
		
		
class LogoutView(View):
	template_name = 'accounts/logout.html'
	redirect_url = 'home'
	
	def get(self, request, *args, **kwargs):
		auth_logout(self.request)
		return redirect('home')
		
		
class ForgottenPasswordResetView(FormView):
	template_name = 'accounts/forgot_password.html'
	form_class = ForgottenPasswordResetForm
	success_url = reverse_lazy('accounts:forgot_password')
	
	def form_valid(self, form):
		try:
			form.save(self.request)
		except User.DoesNotExist:
			pass
		messages.success(self.request, account_strings.PASSWORD_RESET_FORM_SUBMITTED_RESPONSE)
		return super(ForgottenPasswordResetView, self).form_valid(form)
		
		
class PasswordResetView(FormView):
	"""
	Reset user password. Either with provided uid/token get parameters
	or if the user is logged in.
	"""
	template_name = 'accounts/password_reset.html'
	form_class = SetPasswordForm
	success_url = reverse_lazy('home')
	
	def corrupt_link_redirect(self, request, include_message=True):
		if include_message:
			messages.error(self.request, account_strings.PASSWORD_RESET_INVALID_LINK)
		return redirect('accounts:forgot_password')
	
	def get_form(self):
		try:
			user = User.objects.get(pk=self.request.session.get('pw_pk'))
		except User.DoesNotExist:
			return Http404() ## Refine this
		return self.form_class(user, **self.get_form_kwargs())
	
	def post(self, request, *args, **kwargs):
		if not request.session.get('pw_pk') and request.user.is_authenticated:
			request.session['pw_pk'] = request.user.pk
		return super(PasswordResetView, self).post(request, *args, **kwargs)
	
	def get(self, request, *args, **kwargs):
		if request.user.is_authenticated:
			## User is logged in so present them with the password reset form
			request.session['pw_pk'] = request.user.pk
			return super(PasswordResetView, self).get(request, *args, **kwargs)
		try:
			uidb64 = kwargs.get('uid')
			token = kwargs.get('token')
			## Check for both missing specifically so we don't trigger the invalid
			## link message when someone wanders in without a broken uid/token combo
			if uidb64 is None and token is None:
				return self.corrupt_link_redirect(request, include_message=False)
			## One is present meaning the link is guinely broken. Include the message.
			elif uidb64 is None or token is None:
				return self.corrupt_link_redirect(request) ## Failure redirect
			uid = force_text(urlsafe_base64_decode(uidb64))
			user = User.objects.get(pk=uid)
		except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
			return self.corrupt_link_redirect(request) ## Failure redirect
		
		if user is not None and PasswordResetTokenGenerator().check_token(user, token):
			request.session['pw_pk'] = user.pk
			return super(PasswordResetView, self).get(request, *args, **kwargs)
		return self.corrupt_link_redirect(request) ## Failure redirect
	
	def form_valid(self, form):
		try:
			NONSENSE = self.request.user.is_authenticated
			form.save()
			update_session_auth_hash(self.request, form.user)
			## Delete session item
			if self.request.session.get('pw_pk'):
				del self.request.session['pw_pk']
		except User.DoesNotExist:
			pass
		messages.success(
			self.request,
			account_strings.PASSWORD_RESET_SUCCESS if self.request.user.is_authenticated \
			else account_strings.PASSWORD_RESET_SUCCESS + account_strings.PASSWORD_RESET_SUCCESS_LOGIN_REMINDER
		)
		return super(PasswordResetView, self).form_valid(form)
	
		
@method_decorator(login_required(redirect_field_name=None, login_url='login'), name='dispatch')
class ResendEmailVerificationView(FormView):
	template_name = 'accounts/resend_email_verification.html'
	form_class = ResendEmailVerificationForm
	success_url = reverse_lazy('accounts:resend_email_verification') #'/accounts/verify/email/resend'
	
	def get(self, request, *args, **kwargs):
		if request.user.is_email_verified:
			return render(request, self.template_name, {'is_user_email_verified': True})
		return super(ResendEmailVerificationView, self).get(request, *args, **kwargs)
	
	def get_form(self):
		return self.form_class(self.request.user, **self.get_form_kwargs())
	
	def form_valid(self, form):
		try:
			form_message, form_success = form.save()
			if form_success:
				send_verification_email(self.request, self.request.user)
				messages.success(
					self.request,
					account_strings.get_resend_email_verification_success(self.request.user.email)
				)
			else:
				messages.error(self.request, form_message)
		except Exception:
			messages.error(self.request, account_strings.RESEND_EMAIL_VERIFICATION_FAILURE)
		return super(ResendEmailVerificationView, self).form_valid(form)
		
		
class AccountSettingsView(LoginRequiredMixin, FormView):
	"""Account settings: username, email, is_active"""
	template_name = 'accounts/account_settings.html'
	form_class = AccountSettingsForm
	success_url = reverse_lazy('accounts:account_settings')
	login_url = 'login'
	
	def get_form(self, form_class=None):
		return self.form_class(**self.get_form_kwargs(), instance=self.request.user)
	
	def form_valid(self, form):
		saved_user, bool_send_email = form.save()
		if bool_send_email:
			send_verification_email(self.request, saved_user)
		messages.success(self.request, account_strings.ACCOUNT_SETTINGS_UPDATE_SUCCESS)
		return super(AccountSettingsView, self).form_valid(form)
		
		
class AccountProfileView(LoginRequiredMixin, VerifiedEmailMixin, View): # FormView):
	"""
	Edit descriptive user profile information:
	avatar, name, birth_date, gender, country, bio, website
	"""
	template_name = 'accounts/account_profile.html'
	form_class = AccountProfileForm
	success_url = reverse_lazy('accounts:account_profile')
	login_url = 'login'
	
	def get(self, request, *args, **kwargs):
		# Avatar form
		avatar_form = AccountAvatarUploadForm(instance=self.request.user)
		# User profile form
		account_profile_form = AccountProfileForm(instance=self.request.user)
		return render(request, self.template_name, context={
			'avatar_form': avatar_form,
			'account_profile_form': account_profile_form,
		})
	
	def post(self, request, *args, **kwargs):
		# Avatar form
		avatar_form = AccountAvatarUploadForm(instance=self.request.user)
		# User profile form
		account_profile_form = AccountProfileForm(data=request.POST, instance=request.user)
		if account_profile_form.is_valid():
			account_profile_form.save()
			messages.success(self.request, account_strings.ACCOUNT_PROFILE_UPDATE_SUCCESS)
		return render(request, self.template_name, context={
			'avatar_form': avatar_form,
			'account_profile_form': account_profile_form,
		})
		
		
class AccountAvatarUploadView(LoginRequiredMixin, VerifiedEmailMixin, View):
	
	def post(self, request, *args, **kwargs):
		avatar_form = AccountAvatarUploadForm(data=request.POST, files=request.FILES, instance=request.user)
		if avatar_form.is_valid():
			avatar_form.save()
			return JsonResponse({'success': True, 'img_src': request.user.avatar.url, 'errors': []})
		else:
			return JsonResponse({'success': False, 'img_src': request.user.avatar.url, 'errors': avatar_form.errors})
		
		
class AccountDevicesView(LoginRequiredMixin, VerifiedEmailMixin, FormView):
	"""Account mobile settings"""
	template_name = 'accounts/account_devices.html'
	form_class = AccountDevicesForm
	success_url = reverse_lazy('accounts:account_devices')
	login_url = 'login'
	
	def get_form(self, form_class=None):
		return self.form_class(**self.get_form_kwargs(), instance=self.request.user)
	
	def get(self, request, *args, **kwargs):
		return super(AccountDevicesView, self).get(request, *args, **kwargs)
		
	def form_valid(self, form):
		# We can't be certain users haven't messed with the choices, so we'll
		# validate them here again to be sure.
		#country_code = self.
		form.save()
		messages.success(self.request, account_strings.ACCOUNT_PROFILE_UPDATE_SUCCESS)
		return super(AccountDevicesView, self).form_valid(form)
		
class AccountPasswordView(LoginRequiredMixin, FormView):
	"""Account password settings"""
	template_name = 'accounts/account_password.html'
	form_class = ChangePasswordForm
	success_url = reverse_lazy('accounts:account_password')
	login_url = 'login'
	
	def get_form(self, form_class=None):
		form = self.form_class(user=self.request.user, **self.get_form_kwargs())
		return form
		
	def get_form_kwargs(self):
		data = super(AccountPasswordView, self).get_form_kwargs()
		data['request'] = self.request
		return data
		
	def form_valid(self, form):
		form.save()
		update_session_auth_hash(self.request, form.user)
		messages.success(self.request, account_strings.ACCOUNT_PASSWORD_UPDATE_SUCCESS)
		return super(AccountPasswordView, self).form_valid(form)
		
		
class AccountDeactivationView(LoginRequiredMixin, FormView):
	template_name = 'accounts/account_deactivation.html'
	form_class = AccountDeactivationForm
	success_url = '/'
	login_url = 'login'
		
	def get_form_kwargs(self):
		data = super(AccountDeactivationView, self).get_form_kwargs()
		data['request'] = self.request
		return data
	
	def get_form(self, form_class=None):
		return self.form_class(**self.get_form_kwargs(), instance=self.request.user)
	
	def form_valid(self, form):
		try:
			user_to_delete = User.objects.get(id=self.request.user.id)
			form.save()
			# TODO:
			# Send microservice call to delete user from active oltp environment and moved
			# records to user db cache
			# FORNOW:
			# Delete the records to keep tables clean while working on underlying infastructure
			auth_logout(self.request)
			user_to_delete.delete()
			messages.success(self.request, account_strings.ACCOUNT_DEACTIVATION_SUCCESS)
		except Exception as e:
			print(str(e))
			traceback.print_exc()
			messages.error(self.request, account_strings.ACCOUNT_DEACTIVATION_FAILURE)
		return super(AccountDeactivationView, self).form_valid(form)
		
		
		