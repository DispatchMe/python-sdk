import hashlib
import hmac
import base64
import datetime
class HMACSignature(object):

	def __init__(self, secret):
		self.secret = secret

	def get_headers(self, public_key, content_type, md5_of_body, url_path, date_str):
		content_to_sign = ','.join([content_type, md5_of_body, url_path, date_str]).encode('utf-8')
		sha1_sig = self.sha(content_to_sign)
		return {
			'Content-Type': content_type,
			'Date': date_str,
			'Content-MD5': md5_of_body,
			'Authorization': "APIAuth %s:%s" % (public_key, sha1_sig)
		}

	def md5_b64digest(self, payload=b''):
		hash = hashlib.md5()
		hash.update(payload)
		dig = hash.digest()
		return self.base64_encode(dig)

	def base64_encode(self, b):
		b64s = base64.b64encode(b).decode('utf-8')
		return b64s

	def get_hash_content(self, content_type, md5_of_body, url_path, date_str):
		return ','.join([content_type, md5_of_body, url_path, date_str])

	def sha(self, message, algorithm=hashlib.sha1):
		digester = hmac.new(self.secret, message, algorithm)
		return base64.b64encode(digester.digest()).decode("utf-8")

	def format_date(self, timestamp):
		return timestamp.strftime('%a, %d %b %Y %H:%M:%S GMT')

def get_hmac_auth_headers(public_key, secret_key, content_type, body, url_path):
	hmac_sig = HMACSignature(bytes(secret_key, 'utf-8'))
	md5 = hmac_sig.md5_b64digest(b'' if body is None else bytes(body, 'utf-8'))
	date_str = hmac_sig.format_date(datetime.datetime.utcnow())
	return hmac_sig.get_headers(content_type=content_type, md5_of_body=md5,
								   url_path=url_path, date_str=date_str,
								   public_key=public_key)
