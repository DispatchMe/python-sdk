import requests
import json
import urllib

from .errors import ValidationError, RequestError
from .hmac import get_hmac_auth_headers

class Client:
	"""
	client connects to the Dispatch platform using your client credentials.
	"""
	def __init__(self, client_id='', client_secret='', username=None, password=None, api_url="https://api.dispatch.me", auth_mode='bearer', hmac_public_key=None, hmac_secret_key=None):
		"""
		Construct a new client

		:param client_id: Your client_id (received during registration)
		:param client_secret: Your client secret (received during registration)
		:param username: Provide if you are doing an organization-level integration. Leave blank for job sources
		:param password: Provide if you are doing an organization-level integration. Leave blank for job sources
		:param api_url: URL for the API. Defaults to production but you can change this to the sandbox environment for testing.
		:param auth_mode: "bearer" or "hmac"
		:param hmac_public_key
		:param hmac_secret_key
		"""
		self.client_id = client_id
		self.client_secret = client_secret
		self.api_url = api_url
		self.username = username
		self.password = password
		self.__session = requests.Session()
		self.__session.headers.update({
			'Content-Type': 'application/json',
			'Accept': 'application/json'
		})
		self.__auth_mode = auth_mode

		if auth_mode == 'hmac':
			self.__hmac_public_key = hmac_public_key
			self.__hmac_secret_key = hmac_secret_key
		else:
			self.__bearer_token = None

	def __uri(self, path, query=None):
		full = path

		if query is not None:
			full_query = {}
			for k in query:
				full_query['filter[{}]'.format(k)] = query[k]
			full = full + '?' + urllib.urlencode(full_query)
		return full

	def __load_bearer_token(self):
		request_body = {
			'client_id': self.client_id,
			'client_secret': self.client_secret,
		}

		# Organization-level (user) auth
		if self.username is not None:
			request_body['username'] = self.username
			request_body['password'] = self.password
			request_body['grant_type'] = 'password'

		# Account-level (application) auth
		else:
			request_body['grant_type'] = 'client_credentials'

		headers = {
			'Content-Type': 'application/json'
		}
		response = requests.post(self.api_url + self.__uri('/v3/oauth/token'), headers=headers, data=json.dumps(request_body))

		self.__check_error(response)

		json_resp = response.json()
		if 'access_token' in json_resp:
			self.__bearer_token = json_resp['access_token']
			self.__session.headers.update({'Authorization': 'Bearer {}'.format(self.__bearer_token)})
		else:
			raise UserWarning("No access_token key present in response payload")

	def __check_error(self, response):
		if response.status_code >= 200 and response.status_code < 300:
			return

		# Special error type for validation errors
		if response.status_code == 422:
			body = response.json()
			raise ValidationError("Validation failed", body["errors"])

		raise RequestError(response.reason, response.status_code)

	def __do_request(self, method, uri, body=None, files=None, query=None, in_retry=False, parse_response=True):

		if self.__auth_mode is 'bearer':
			if self.__bearer_token is None:
				self.__load_bearer_token()

		payload = None
		if body is not None:
			payload = json.dumps(body)

		full_uri = self.__uri(uri, query)

		func = getattr(self.__session, method)

		if self.__auth_mode is 'hmac':
			headers = get_hmac_auth_headers(self.__hmac_public_key, self.__hmac_secret_key, 'application/json', payload, full_uri)
		else:
			headers = None

		request_url = self.api_url + full_uri
		resp = func(request_url, data=payload, files=files, headers=headers)

		# If we get a 401, grab a new bearer token and retry the request ONCE.
		# This should only happen when a bearer token expires.
		if resp.status_code is 401 and self.__auth_mode is 'bearer' and not in_retry:
			self.__load_bearer_token()

			return self.__do_request(method, request_url, body=body, query=query, in_retry=True, parse_response=parse_response)

		self.__check_error(resp)

		json_resp = resp.json()
		# Grab the first key in the response that isn't "meta"
		if parse_response:
			for key in json_resp:
				if key != 'meta':
					return json_resp[key]

			raise UserWarning("Unexpected response body")
		return json_resp

	def list(self, endpoint, query):
		return self.__do_request('get', endpoint, query=query)
	def get(self, endpoint, id):
		return self.__do_request('get', endpoint + '/{}'.format(id))
	def create(self, endpoint, attrs):
		return self.__do_request('post', endpoint, body=attrs)
	def update(self, endpoint, id, attrs):
		return self.__do_request('patch', endpoint + '/{}'.format(id), body=attrs)
	def delete(self, endpoint, id):
		return self.__do_request('delete', endpoint + '/{}'.format(id))

	def create_appointment(self, attrs={}):
		"""
		Create an appointment

		:param attrs: Dictionary of attributes for this appointment
		:return: Appointment object
		"""
		return self.create('/v3/appointments', attrs)

	def update_appointment(self, id, attrs):
		"""
		Update an appointment

		:param id: ID of the appointment to update
		:param attrs: Dictionary of attributes to update
		:return: Appointment object
		"""
		return self.update('/v3/appointments', id, attrs)

	def list_appointments(self, query):
		"""
		Get a list of appointments matching the query.

		:param query: Dictionary of query filters
		:return: Array of appointments
		"""
		return self.list('/v3/appointments', query)

	def get_appointment(self, id):
		"""
		View a single appointment by ID

		:param id: ID of the appointment
		:return: Appointment object
		"""
		return self.get('/v3/appointments', id)

	def add_note(self, job_id, text):
		"""
		Add a note to a job

		:param job_id: The ID of the job
		:param text: Text for the note
		:return: Attachment object
		"""
		attrs = {
			'entity_type': 'Job',
			'entity_id': job_id,
			'description': text,
		}
		return self.create('/v3/attachments', attrs)

	def upload_photo(self, path=None, fileobj=None):
		"""
		Upload a photo

		Must provide either path or fileobj params

		:param path: Path to the local file
		:param fileobj: File-like object
		:return: UID (file token) for the file
		"""
		files = {}
		if path is not None:
			files['media'] = open(path, 'rb')
		elif fileobj is not None:
			files['media'] = fileobj
		else:
			raise ValueError('Must provide either path or fileobj to upload a photo')

		response = self.__do_request('post', '/v3/datafiles', files=files)
		if 'uid' not in response:
			raise UserWarning('No uid property in upload response')

		return response['uid']
	
	def add_photo(self, job_id, path=None, fileobj=None):
		"""
		Upload a photo and add it to a given job

		:param job_id: ID of the job
		:param path: Path to local file
		:param fileobj: File-like object to upload
		:return: Attachment object
		"""
		file_token = self.upload_photo(path, fileobj)
		attrs = {
			'entity_type': 'Job',
			'entity_id': job_id,
			'file_token': file_token
		}

		return self.create('/v3/attachments', attrs)

	def delete_attachment(self, id):
		"""
		Delete an attachment (note or photo)

		:param id: The ID of the attachment
		"""
		return self.delete('/v3/attachments', id)

	def list_attachments(self, query):
		"""
		View all attachments matching the query

		:param query: Dictionary defining query filters.
		:return: Array of attachments
		"""
		return self.list('/v3/attachments', query)

	def get_attachment(self, id):
		"""
		View a single attachment

		:param id: ID of the attachment
		:return: Attachment object
		"""
		return self.get('/v3/attachments', id)

	def create_brand(self, attrs={}):
		"""
		Create a brand

		:param attrs: Dictionary of attributes for this brand
		:return: Brand object
		"""
		return self.create('/v3/brands', attrs)

	def update_brand(self, id, attrs):
		"""
		Update a brand

		:param id: ID of the brand to update
		:param attrs: Dictionary of attributes to update
		:return: Brand object
		"""
		return self.update('/v3/brands', id, attrs)

	def list_brands(self, query):
		"""
		Get a list of brands matching the query.

		:param query: Dictionary of query filters
		:return: Array of brands
		"""
		return self.list('/v3/brands', query)

	def get_brand(self, id):
		"""
		View a single brand by ID

		:param id: ID of the brand
		:return: Brand object
		"""
		return self.get('/v3/brands', id)

	def upsert_customer(self, organization_id=None, attrs={}):
		"""
		Upsert a customer. This will attempt to find an existing customer using the data you provide, and will create a new one if no match is found.
		
		:param organization_id: ID of the organization this customer belongs to. You can leave this blank if you are authenticating as an organization
		:param attrs: Dictionary of attributes for the customer
		:return: Customer object
		"""
		if organization_id is not None:
			attrs['organization_id'] = organization_id
		return self.create('/v3/customers', attrs)

	def update_customer(self, id, attrs):
		"""
		Update a customer

		:param id: ID of the customer
		:param attrs: Dictionary of attributes to update
		:return: Customer object
		"""
		return self.update('/v3/customers', id, attrs)

	def list_customers(self, query):
		"""
		Get a list of customers matching the query.

		:param query: Dictionary of query filters
		:return: Array of customers
		"""
		return self.list('/v3/customers', query)

	def get_customer(self, id):
		"""
		View a single customer by ID

		:param id: ID of the customer
		:return: Customer object
		"""
		return self.get('/v3/customers', id)

	def delete_customer(self, id):
		"""
		Delete a single customer by ID

		:param id: ID of the customer
		"""
		return self.delete('/v3/customers', id)

	def create_job(self, organization_id=None, attrs={}):
		"""
		Create a job

		:param organization_id: ID of the assigned organization. Leave this blank if you are authenticating as an organization
		:param attrs: Dictionary of attributes for this job
		:return: Job object
		"""
		if organization_id is not None:
			attrs['organization_id'] = organization_id
		return self.create('/v3/jobs', attrs)

	def update_job(self, id, attrs):
		"""
		Update a job

		:param id: ID of the job to update
		:param attrs: Dictionary of attributes to update
		:return: Job object
		"""
		return self.update('/v3/jobs', id, attrs)

	def list_jobs(self, query):
		"""
		Get a list of jobs matching the query.

		:param query: Dictionary of query filters
		:return: Array of jobs
		"""

		return self.list('/v3/jobs', query)

	def get_job(self, id):
		"""
		View a single job by ID

		:param id: ID of the job
		:return: Job object
		"""
		return self.get('/v3/jobs', id)

	def accept_job(self, job_id):
		"""
		Accept an offered job.

		:param job_id: ID of the job to accept
		"""
		return self.__do_request('post', '/v3/jobs/{}/accept'.format(job_id))

	def reject_job(self, job_id):
		"""
		Reject an offered job

		:param job_id: ID of the job to reject
		"""
		return self.__do_request('post', '/v3/jobs/{}/reject'.format(job_id))

	def upsert_organization(self, attrs={}):
		"""
		Upsert an organization. This will attempt to find an existing organization using the data you provide, and will create a new one if no match is found.

		:param attrs: Dictionary of attributes for the organization
		:return: Organization object
		"""
		return self.create('/v3/organizations', attrs)

	def update_organization(self, id, attrs):
		"""
		Update an organization

		:param id: ID of the organization
		:param attrs: Dictionary of attributes to update
		:return: Organization object
		"""
		return self.update('/v3/organizations', id, attrs)

	def list_organizations(self, query):
		"""
		Get a list of organizations matching the query.

		:param query: Dictionary of query filters
		:return: Array of organizations
		"""
		return self.list('/v3/organizations', query)

	def get_organization(self, id):
		"""
		View a single organization by ID

		:param id: ID of the organization
		:return: Organization object
		"""
		return self.get('/v3/organizations', id)

	def get_surveys_for_job(self, job_id):
		"""
		View a list of customer surveys for a given job

		:param job_id: ID of the job
		:return: Array of surveys
		"""
		return self.list('/v3/survey_responses', {
			'job_id': job_id
		})


	def create_user(self, organization_id=None, attrs={}):
		"""
		Create a user
	
		:param organization_id: Organization this user belongs to. Leave blank if you are authenticated as an organization.
		:param attrs: Dictionary of attributes for this user
		:return: User object
		"""
		return self.create('/v3/users', attrs)

	def update_user(self, id, attrs):
		"""
		Update a user

		:param id: ID of the user to update
		:param attrs: Dictionary of attributes to update
		:return: User object
		"""
		return self.update('/v3/users', id, attrs)

	def list_users(self, query):
		"""
		Get a list of users matching the query.

		:param query: Dictionary of query filters
		:return: Array of users
		"""
		return self.list('/v3/users', query)

	def get_user(self, id):
		"""
		View a single user by ID

		:param id: ID of the user
		:return: User object
		"""
		return self.get('/v3/users', id)
