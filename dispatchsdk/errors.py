import json

class ValidationError(Exception):
	def __init__(self, message, errors=[]):
		super(ValidationError, self).__init__(message + ' -- ' + json.dumps(errors))
		self.errors = errors

class RequestError(Exception):
	def __init__(self, message, code):
		super(RequestError, self).__init__(message)
		self.code = code
