# accounts/mixins.py

from django.shortcuts import redirect



class VerifiedEmailMixin:
	"""
	Deny a request if a user's email is not yet verified
	"""
	def dispatch(self, request, *args, **kwargs):
		if not request.user.is_email_verified:
			return redirect('accounts:resend_email_verification')
		return super().dispatch(request, *args, **kwargs)

