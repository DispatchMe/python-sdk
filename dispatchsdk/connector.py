import requests
import hashlib
import hmac
import binascii
import gzip
from .errors import ValidationError, RequestError

class ConnectorClient:
	def __init__(self, public_key, secret_key, hub_url='https://connect.dispatch.me'):
		self.public_key = public_key
		self.secret_key = bytearray.fromhex(secret_key)
		self.hub_url = hub_url

	def __check_error(self, response):
		if response.status_code >= 200 and response.status_code < 300:
			return

		raise RequestError(response.reason, response.status_code)

	def __get_signature(key, body):
	    digester = hmac.new(key, body, hashlib.sha256)
	    return binascii.hexlify(digester.digest()).decode('utf-8')

	def __make_signed_request(self, uri, body, method, compress=False, headers={}):
		func = getattr(requests, method)

		use_body = body
		if compress:
			use_body = gzip.compress(body)

		signature = self.__get_signature(self.secret_key, use_body)
		headers['X-Dispatch-Key'] = self.public_key
		headers['X-Dispatch-Signature'] = signature

		resp = func(self.hub_url + uri, headers=headers, data=compressed_body)
		self.__check_error(resp)
		return resp.json()

	def put_data(self, data):
		if isinstance(data, str):
			data = bytes(data, 'utf-8')
		return self.__make_signed_request('/agent/in', data, 'post', compress=True)
