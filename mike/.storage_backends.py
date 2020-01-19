# mike/storage_backends.py

import boto3
from storages.backends.s3boto3 import S3Boto3Storage
from storages.utils import setting

from botocore.signers import CloudFrontSigner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

from django.conf import settings
from django.utils.encoding import filepath_to_uri



def rsa_signer(message):
	#### .pem is the private keyfile downloaded from CloudFront keypair
	with open(settings.CLOUDFRONT_PK_FILE_NAME, 'rb') as key_file:
		private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)
		signer = private_key.signer(padding.PKCS1v15(), hashes.SHA1())
		signer.update(message)
	return signer.finalize()
		
		
def generate_signed_cloudfront_url(path=None, cloudfront_url=settings.CLOUDFRONT_URL, *args, **kwargs):
	if path is None:
		raise ValueError("Must provide a path for the CloudFront url to sign")
	
	key_id = kwargs.get('key_id') or settings.CLOUDFRONT_KEY_ID
	expiry = kwargs.get('expiry') or 120
	current_time = datetime.datetime.utcnow()
	expire_date = current_time + datetime.timedelta(seconds=expiry)
	rsa_signer_ = kwargs.get('rsa_signer') or rsa_signer
	
	cloudfront_signer = CloudFrontSigner(key_id, rsa_signer_)
	url = cloudfront_url + path
	
	# Create a signed url that will be valid until the specific expiry date provided using a canned policy
	signed_url = cloudfront_signer.generate_presigned_url(
		url,
		date_less_than=expire_date
	)
	return signed_url
		
		
		
class StaticStorage(S3Boto3Storage):
	location = settings.AWS_STATIC_LOCATION
	cloudfront = True
	cloudfront_params = {
		'expiry': 3600
	}
	
	def __init__(self, *args, **kwargs):
		super(StaticStorage, self).__init__(*args, **kwargs)
	
	def url(self, name, parameters=None, expire=None):
		if hasattr(self, 'cloudfront') and self.cloudfront == True:
			name = self._normalize_name(self._clean_name(name))
			path = filepath_to_uri(name)
			cloudfront_url = self.cloudfront_params.get('cloudfront_url') or setting('CLOUDFRONT_URL', None)
			url = generate_signed_cloudfront_url(
				path=path, 
				cloudfront_url=cloudfront_url,
				**self.cloudfront_params
			)
			return url
		else:
			return super(StaticStorage, self).url(self, name, parameters, expire)
	
	

class PublicMediaStorage(S3Boto3Storage):
	location = settings.AWS_PUBLIC_MEDIA_LOCATION
	file_overwrite = False
	cloudfront = True
	cloudfront_params = {}
	
	def __init__(self, *args, **kwargs):
		super(PublicMediaStorage, self).__init__(*args, **kwargs)
	
	def url(self, name, parameters=None, expire=None):
		if hasattr(self, 'cloudfront') and self.cloudfront == True:
			name = self._normalize_name(self._clean_name(name))
			path = filepath_to_uri(name)
			cloudfront_url = setting('CLOUDFRONT_URL', self.cloudfront_params.get('cloudfront_url'))
			url = generate_signed_cloudfront_url(
				path=path, 
				cloudfront_url=cloudfront_url,
				**self.cloudfront_params
			)
			return url
		else:
			return super(PublicMediaStorage, self).url(self, name, parameters, expire)
	
	
