# core/s3_utils.py

import boto3
from storages.utils import setting

from django.conf import settings
from django.contrib.auth import get_user_model



user = get_user_model()


def get_resource(config: dict={}):
	"""Loads the s3 resource.
	
	Expects AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to be in the environment
	or in a config dictionary.
	Looks in the environment first."""
	
	s3 = boto3.resource(
		's3',
		aws_access_key_id=setting('AWS_ACCESS_KEY_ID', config.get('AWS_ACCESS_KEY_ID')),
		aws_secret_access_key=setting('AWS_SECRET_ACCESS_KEY', config.get('AWS_SECRET_ACCESS_KEY'))
	)
	return s3
	
	
def get_client(config: dict={}):
	"""Loads the s3 resource.
	
	Expects AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to be in the environment
	or in a config dictionary.
	Looks in the environment first."""
	
	s3 = boto3.client(
		's3',
		aws_access_key_id=setting('AWS_ACCESS_KEY_ID', config.get('AWS_SECRET_ACCESS_KEY')),
		aws_secret_access_key=setting('AWS_SECRET_ACCESS_KEY', config.get('AWS_SECRET_ACCESS_KEY'))
	)
	return s3
	
	
def get_bucket(s3, s3_uri: str):
	"""Get the bucket from the resource.
	A thin wrapper, use with caution.
	
	Example usage:
	
	>> bucket = get_bucket(get_resource(), s3_uri_prod)"""
	return s3.Bucket(s3_uri)


def delete_s3_file(file_name, bucket_name, location=None, **config):
	
	try:
		s3 = boto3.client(
			's3', 
			aws_access_key_id=setting('AWS_ACCESS_KEY_ID', config.get('AWS_ACCESS_KEY_ID')), 
			aws_secret_access_key=setting('AWS_SECRET_ACCESS_KEY', config.get('AWS_SECRET_ACCESS_KEY'))
		)
		key = location + '/' + file_name if location else file_name
		response = s3.delete_object(Bucket=bucket_name, Key=key)
	
	except Exception as e:
		print(str(e))
		# log this somehow
		

def isfile_s3(bucket_name, key: str) -> bool:
	"""
		Returns T/F whether the file exists
		https://stackoverflow.com/questions/33842944/check-if-a-key-exists-in-a-bucket-in-s3-using-boto3
	"""
	bucket = get_bucket(get_resource(), bucket_name)
	objs = list(bucket.objects.filter(Prefix=key))
	return len(objs) > 0
	
	
	