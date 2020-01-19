# accounts/tokens.py

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import six



class TokenGenerator(PasswordResetTokenGenerator):
	def _make_hash_value(self, user, timestamp):
		return (
			six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.is_active)
		)

class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
	def _make_hash_value(self, user, timestamp):
		return (
			six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.is_active) + \
			six.text_type(user.email) + six.text_type(user.email_verification_sent_count)
		)

services_token = TokenGenerator()
email_verification_token = EmailVerificationTokenGenerator()


