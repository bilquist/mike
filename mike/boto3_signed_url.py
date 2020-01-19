# titan/boto3_signed_url.py


from botocore.signers import CloudFrontSigner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

from django.conf import settings



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
		
key_id = settings.CLOUDFRONT_KEY_ID
url = 'd1on7f8lkpfomn.cloudfront.net/media/2test2.jpg'
current_time = datetime.datetime.utcnow()
expire_date = current_time + datetime.timedelta(minutes=2)
cloudfront_signer = CloudFrontSigner(key_id, rsa_signer)

# Create a signed url that will be valid until the specific expiry date provided using a canned policy
signed_url = cloudfront_signer.generate_presigned_url(
	url,
	date_less_than=expire_date
)
print(signed_url)

