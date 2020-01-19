# accounts/strings.py

# Notifications email address
NOTIFICATION_EMAIL = 'notifications@michaelhatheway.com'

# Email verification: email body subject and text
EMAIL_VERIFICATION_MAIL_SUBJECT = 'Verify your account'
def get_email_verification_mail_body(activation_link):
	EMAIL_VERIFICATION_MAIL_BODY = (
		'You have created an account on MichaelHatheway.com with this email address. You are one '
		'click away from activating it. If this wasn\'t you, please ignore this email.\n'
		f'{activation_link}'
	)
	return EMAIL_VERIFICATION_MAIL_BODY

# Email verification: link expired so please verify with the new one message
EMAIL_VERIFICATION_RESENT_MESSAGE = (
	'The activiation link you clicked expired. Another one has been sent. '
	'Please use it to verify your email within 48 hours.'
)

# Confirm user email address was successfully verified
EMAIL_VERIFICATION_SUCCESS = 'Your email address was successfully verified.'

# Let the user know they already verified their address and do not need to do it again
EMAIL_VERIFICATION_ALREADY_VERIFIED = (
	'Your email address has already been verified.'
)

EMAIL_VERIFICATION_TOKEN_INVALID = (
	'This link is invalid. Please submit a new email verification request.'
)

# Password Reset
PASSWORD_RESET_SUBJECT = "Reset your password"
def get_password_reset_body(username, password_reset_link):
	PASSWORD_RESET_BODY = (
		f'Hello {username},\n\n'
		'We got a request to reset your MichaelHatheway password. If it wasn\'t you, '
		'ignore this message and your password won\'t be changed.\n'
		f'{password_reset_link}'
	)
	return PASSWORD_RESET_BODY
	
PASSWORD_RESET_FORM_SUBMITTED_RESPONSE = (
	'Thank you. A password reset email will be sent to the address you entered '
	'if there is an associated account.'
)
	
PASSWORD_RESET_INVALID_LINK = 'This link is no longer valid.'
PASSWORD_RESET_SUCCESS = 'Your password has been saved!'
PASSWORD_RESET_SUCCESS_LOGIN_REMINDER = ' Please log in with your new password.'


# Email Verification Email Messages
def get_resend_email_verification_success(email):
	RESEND_EMAIL_VERIFICATION_SUCCESS = f'The verification email was resent successfully to {email}'
	return RESEND_EMAIL_VERIFICATION_SUCCESS
	
RESEND_EMAIL_VERIFICATION_FAILURE = 'There was an error resending your verification email. Please try again.'

RESEND_EMAIL_VERIFICATION__NEW_EMAIL_ALREADY_EXISTS = (
	'Sorry, the email you entered has already been taken by another account.'
)

RESEND_EMAIL_VERIFICATION__EMAIL_ALREADY_VERIFIED = (
	'You have already verified your email address.'
)

# Account Settings
ACCOUNT_SETTINGS_UPDATE_SUCCESS = 'Your account was updated successfully.'
ACCOUNT_PROFILE_UPDATE_SUCCESS = 'Your profile was updated successfully.'

# Account Password
ACCOUNT_PASSWORD_UPDATE_SUCCESS = 'Your password was updated successfully.'

# Account Deactivation
ACCOUNT_DEACTIVATION_SUCCESS = 'Your account was successfully deleted.'
ACCOUNT_DEACTIVATION_FAILURE = 'There was an error deleting your account. Please try again.'
ACCOUNT_DEACTIVATION_SUBJECT = 'Your account was deleted'
def get_account_deactivation_body(username):
	ACCOUNT_DEACTIVATION_EMAIL_BODY = (
		f'Hi {username},\n\nYour MichaelHatheway account was successfully deleted. '
		'We appreciate the time you spent with us. Feel free to rejoin anytime!\n\nSincerely,\nThe MichaelHatheway Team'
	)
	return ACCOUNT_DEACTIVATION_EMAIL_BODY
	

