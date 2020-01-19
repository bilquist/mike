# accounts/utils.py

import re
import random
import string

from django.contrib.auth import get_user_model
from django.core import validators
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.forms import ValidationError
from django.utils.deconstruct import deconstructible
from django.utils.encoding import force_bytes, force_text
from django.utils.http import is_safe_url, urlsafe_base64_encode, urlsafe_base64_decode
from django.shortcuts import reverse
from django.utils.translation import gettext_lazy as _

from accounts import strings as account_strings
from accounts.tokens import email_verification_token



@deconstructible
class CustomUsernameValidator(validators.RegexValidator):
	"""Validator for custom usernames"""
	regex= r'^[-\w]+$'
	message = _(
		'Letters, numbers, dashes, and underscores only. Username must be between 3 and 20 characters.'
	)
	flags = re.ASCII
	
	
@deconstructible
class USZipCodeValidator(validators.RegexValidator):
	"""Validator for US zip codes"""
	regex = r'(\d{5})([- ])?(\d{4})?'
	message = _(
		'Please only enter U.S. zip codes. Support for international zip codes is in development.'
	)
	flags = re.ASCII


def username_blacklist_validator(value):
	"""Reserved usernames we disallow users from registering."""
	reserved_usernames = [
		'root',
		'admin',
		'sysadmin',
	]
	if value in reserved_usernames:
		raise ValidationError(_('%(value) is not available.'), params={'value': value},)
		
		
def send_verification_email(request, user):
	""" Send email verification to user """
	uid = urlsafe_base64_encode(force_bytes(user.pk)) #.decode() ## Why did this work in another project?
	token = email_verification_token.make_token(user)
	activation_link = request.build_absolute_uri(
		#f'{reverse("verify_email")}?uid={uid}&token={token}'
		f'{reverse("accounts:verify_email", kwargs={"uid": uid, "token": token})}'
	)
	
	mail_subject = account_strings.EMAIL_VERIFICATION_MAIL_SUBJECT
	mail_body = account_strings.get_email_verification_mail_body(activation_link)
	from_email = account_strings.NOTIFICATION_EMAIL
	send_mail(
		mail_subject,
		mail_body,
		from_email,
		[user.email] ## to_email
	)
	
	
def generate_permalink_id(N):
	return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(N))
	