# -*- coding: utf-8 -*-

import argparse
from backports.pbkdf2 import pbkdf2_hmac, compare_digest
import binascii
import cgi
import hashlib
import json
import pprint
import os
import mohawk
import MySQLdb
import random
import re
import sys
import time
import wsgiref.simple_server as wsgi_simple_server

# Import config-file
import config as ba_config


class BAPathDispatcher:
	"""
	Directs requests to path, using methods specified,
	to the appropriate handler. Will handle each request
	according to the set HTTP Content-Type header, as well.

	E.g., "POST /foo" might be redirected to a foo_handler
	function. Then, if the request was made using Content-Type:
	application/json, it would be expected that the data sent
	in the HTTP stream is pure JSON, and so JSON-parser would
	be applied to the data.
	"""

	def __init__(self):
		self.pathmap = { }

	def __parse_request__(self, http_environ):
		http_environ['params'] = {}

		if (http_environ.has_key('PATH_INFO') != True):
			return (None, None)

		if (http_environ.has_key('REQUEST_METHOD') != True):
			return (None, None)

		path = http_environ['PATH_INFO']
		method = http_environ['REQUEST_METHOD'].lower()

		#
		# In the case of Content-Type HTTP header not specified..
		#

		if (http_environ.has_key('CONTENT_TYPE') != True):
			http_environ['CONTENT_TYPE'] = 'text/plain'


		if (http_environ['CONTENT_TYPE'] == 'text/plain'):
			if (method == 'get'):
				try:
					params = cgi.FieldStorage(
						http_environ['wsgi.input'],
						environ=http_environ
					)

					http_environ['params'] = {
						key: params.getvalue(key) \
							for key in params
					}

				except:
					# Something went wrong; error will be generated later,
					# possibly by 404 handler or by handling function.
					pass


		#
		# Handle JSON content from clients
		#

		elif (http_environ['CONTENT_TYPE'] == 'application/json'):
			if ((method == 'post') or (method == 'put')):
				try:
					request_body_size = int(
						http_environ.get(
							'CONTENT_LENGTH',
							0
						)
					)

				except (ValueError):
					request_body_size = 0

				try:
					request_body = \
						http_environ['wsgi.input'].read(
						request_body_size
					)

					http_environ['params'] = json.loads(
						request_body
					)

				except:
					pass

		#
		# Now handle form-like-content from clients.
		#

		elif (http_environ['CONTENT_TYPE'] == \
			'application/x-www-form-urlencoded'):
			post_env = http_environ.copy()
			post_env['QUERY_STRING'] = ''

			if ((method == 'post') or (method == 'put')):
				try:
					post = cgi.FieldStorage(
						fp=http_environ['wsgi.input'],
						environ=post_env,
						keep_blank_values=True
					)

					http_environ['params'] = {
						key: post.getvalue(key) \
							for key in post
					}

				except:
					pass

		#
		# Unsupported method issued.
		#

		else:
			pass

		return (method, path)


	def __req_params_mohawk_str_get__(self, http_environ):
		params_keys = http_environ['params'].keys()
		params_keys.sort()

		hawk_str = ''

		for param_key in params_keys:
			if (len(hawk_str) > 0):
				hawk_str += '&'

			hawk_str += param_key +\
				 '=' +\
				str(http_environ['params'][param_key])

		return hawk_str


	def __response__(self, http_environ, mohawk_sig_res,
		start_response, http_resp_num, resp_headers_extra, json_data):
		"""
		Return a HTTP status, and a JSON response.
		The JSON-data is specified by json_data,
		in any way desireable.
		"""

		resp_header_content_type = 'application/json'
		resp_body = json.dumps(json_data)

		if ((http_resp_num >= 200) and (http_resp_num <= 299)):
			resp_status_text = 'OK'

		elif (http_resp_num == 404):
			resp_status_text = 'Not Found'

		else:
			resp_status_text = 'Error'

		resp_headers = [
			('Content-type', resp_header_content_type),
			('Cache-Control', 'no-cache'),
			('Pragma', 'no-cache')
		]

		if (resp_headers_extra != None):
			resp_headers += resp_headers_extra

		#
		# If we are provided with a Receiver (Hoawk) object,
		# attempt to digitally sign our response.
		#

		if (mohawk_sig_res is not None):
			mohawk_sig_res.respond(
				content=resp_body,
				content_type=resp_header_content_type
			)

			resp_headers.append(
				(
					'Server-Authorization', \
					mohawk_sig_res.response_header. \
						encode("ascii")
				)
			)


		start_response(
			str(http_resp_num) + \
				 ' ' + \
				 resp_status_text,
			resp_headers
		)

		return resp_body


	def __call__(self, http_environ, start_response):
		handler_info = None
		(method, path) = self.__parse_request__(http_environ)

		if ((method != None) and (path != None)):
			handler_info = self.pathmap.get(
				(method, path),
				None
			)

		if (handler_info == None):
			return self.__response__(
				None,
				None,
				start_response,
				404,
				None,
				{ 'error': 'Not found.' }
			)


		#
		# Check if signature of request validates.
		#

		try:
			hawk_str = self.__req_params_mohawk_str_get__(
				http_environ
			)

			db_conn = ba_db_connect()

			mohawk_sender_ids = []

			mohawk_sig_res = ba_signature(
				db_conn,
				http_environ,
				hawk_str,
				mohawk_sender_ids
			)


		except:
			# Note: Do never return the exception string from
			# mohawk, it might contain the secret MAC
			return self.__response__(
				http_environ,
				None,
				start_response,
				401,
				None,
				{
					'error': 'Signature validation of ' + \
						'your request failed.'
				}
			)

		if (mohawk_sig_res != None):
			if (ba_acl_check(
				mohawk_sender_ids,
				http_environ['PATH_INFO']
			) != True):

				return self.__response__(
					http_environ,
					None,
					start_response,
					401,
					None,
					{
						'error': 'Access to ' + \
							'resource is denied'
					}
				)


		(http_resp_num, resp_headers_extra, data) = \
		handler_info['handler'](
			http_environ,
			start_response,
			handler_info['args_extra']
		)

		return self.__response__(
			http_environ,
			mohawk_sig_res,
			start_response,
			http_resp_num,
			resp_headers_extra,
			data
		)


	def register(self, method, path, function, args_extra = None):
		"""
		Register handler function. Save a reference to the function
		when the specified path and method combination is called, and
		also what extra arguments are to be sent to the function.
		"""

		self.pathmap[(method.lower(), path)] = {
			'handler' : function,
			'args_extra' : args_extra
		}

		return function


#
# Database stuff
#

def ba_db_connect():
	"""
	Try to connect to DB, as per configuration.
	"""

	db_conn = MySQLdb.connect(
		ba_config.BA_DB_SERVER,
		ba_config.BA_DB_USERNAME,
		ba_config.BA_DB_PASSWORD,
		ba_config.BA_DB_NAME
	)

	return db_conn

def ba_db_create_tables():
	"""
	Create tables to store our data.
	"""

	db_conn = ba_db_connect()

	#
	# Check if accounts table exists, and if not, create.
	#

	db_cursor = db_conn.cursor()
	db_cursor.execute(
		"SHOW TABLE STATUS LIKE '%accounts%'"
	)
	db_table_status = db_cursor.fetchall()

	table_create_accounts = 0

	try:
		if (db_table_status[0][0] == 'accounts'):
			table_create_accounts = 0

	except IndexError:
		table_create_accounts = 1

	db_cursor.close()


	if (table_create_accounts == 1):
		db_cursor = db_conn.cursor()
		db_cursor.execute(
			"CREATE TABLE `accounts` (			\
			  `id` bigint(20) NOT NULL AUTO_INCREMENT,	\
			  `enabled` int(11) NOT NULL DEFAULT '0', 	\
			  `username` varchar(128) NOT NULL, 		\
			  `password_hashed` varchar(256) NOT NULL, 	\
			  `salt` varchar(128) NOT NULL, 		\
			  `created_at` bigint(20) NOT NULL, 		\
			  `updated_at` bigint(20) DEFAULT NULL, 	\
			  PRIMARY KEY (`id`), 				\
			  UNIQUE KEY `username` (`username`) 		\
			) ENGINE=InnoDB DEFAULT CHARSET=utf8		\
		")

		db_cursor.close()

	#
	# Check if nonce table exists and create
	# if not.

	db_cursor = db_conn.cursor()
	db_cursor.execute(
		"SHOW TABLE STATUS LIKE '%nonce'"
	)
	db_table_status = db_cursor.fetchall()

	table_create_nonce = 0

	try:
		if (db_table_status[0][0] == 'nonce'):
			table_create_nonce = 0

	except:
		table_create_nonce = 1


	if (table_create_nonce == 1):
		db_cursor = db_conn.cursor()
		db_cursor.execute(
			"CREATE TABLE `nonce` (				\
				`id` bigint(20) NOT NULL AUTO_INCREMENT,\
				`nonce_key_hash` varchar(64) NOT NULL,	\
				`timestamp` bigint(20) NOT NULL, 	\
				KEY (nonce_key_hash),			\
				PRIMARY KEY (`id`)			\
			) ENGINE=InnoDB DEFAULT CHARSET=utf8		\
		")

		db_cursor.close()

	db_conn.commit()

	db_conn.close()


#
# Input check routines
#

def ba_req_input_check_username(username_str):
	"""
	Do an input check on username. It must adhere
	to specific requirements (a-z (lowercase), 0-9 only,
	longer or equal to 4 chars, shorter or equal than 128 chars,
	first chars only a-z).
	"""

	if (len(username_str) < 4):
		return False

	if (len(username_str) > 128):
		return False

	re_username_check = re.compile('^([a-z]{4})([a-z0-9]*)$')

	if (re_username_check.match(username_str) == None):
		return False

	return True


def ba_req_input_check_password(password_str):
	"""
	Do input check on password. Only allow
	printable ASCII characters. Minimum length
	of password is 6 characters, and maximum
	length is 100 characters.
	"""

	try:
		# Check if password is ASCII
		password_str.decode('ascii')

	except:
		return False

	if (len(password_str) < 6):
		return False

	if (len(password_str) > 100):
		return False

	for i in range(0, len(password_str)):
		# Only allow printable ASCII
		if ((ord(password_str[i]) < 32)
			or (ord(password_str[i]) > 126)):
			return False

	return True

#
# Mohawk related functions
#

def ba_signature_lookup_sender(sender_id):
	"""
	Check if we got anything on this sender_id.
	This would be found in our configuration file.
	This includes unique secret key.
	"""

	if (ba_config.BA_MOHAWK_SENDERS.has_key(sender_id)):
		return ba_config.BA_MOHAWK_SENDERS[sender_id]

	else:
		raise LookupError('unknown sender')

def ba_signature(db_conn, http_environ, data, mohawk_sender_ids):
	"""
	Validate request-signature from other end.
	Make sure it has a valid digital signature,
	so we can be sure that the other end
	is who he says he is.

	Most of the data required by Mohawk is constructed
	from http_environ variable -- such as HTTP Content-Cype
	header -- while the rest, the data, is provided by data
	variable.

	Note: This is NOT decryption of data, only
	validation of digital signature.

	Note: This function should be called before any sensitive
	database transaction is run.

	For documentation of mohawk, see:
	http://mohawk.readthedocs.org/en/latest/usage.html#receiving-a-request

	"""

	def ba_signature_nonce_seen(sender_id, nonce, timestamp):
		"""
		Check if we have already seen this sender_id + nonce token + timestamp.
		We do this by look for it in our DB, and if it is not found,
		we record it in the database for future callers.

		This will guarantee that users cannot use their nonce tokens
		again -- nor someone else's.

		Note that this is implemented as a sub-function so that we
		can inherit the db_conn object from the parent.
		"""

		timestamp_now = int(time.time())

		#
		# In ~2% of cases we do housekeeping; here
		# we remove expired nonce tokens.
		#

		if (random.randint(0, 100) <= 2):
			db_cursor = db_conn.cursor()
			db_cursor.execute(
				"DELETE FROM nonce WHERE timestamp < %s",
				[
					timestamp_now - \
						(ba_config.\
						BA_MOHAWK_NONCE_EXPIRY * 10)
				]
			)

			db_cursor.close()

			db_conn.commit()

		#
		# Construct unique hash-key we look
		# to look up in our DB for already
		# used tokens.
		#

		nonce_key_prehash = '{sender_id}:{nonce}:{timestamp}'.format(
			sender_id=sender_id,
			nonce=nonce,
			timestamp=timestamp
		)
		nonce_key_hash = hashlib.sha256(
			nonce_key_prehash
		).hexdigest()


		db_cursor = db_conn.cursor()
		db_cursor.execute(
			"SELECT id FROM nonce WHERE nonce_key_hash = %s",
			[ nonce_key_hash ]
		)

		db_nonce_rows = db_cursor.fetchmany(1)

		db_cursor.close()

		if (len(db_nonce_rows) > 0):
			# This nonce token has been used before.
			return True

		else:
			#
			# nonce has not been used before,
			# record it in DB and return False
			#

			db_cursor = db_conn.cursor()
			db_cursor.execute(
				"INSERT INTO nonce " + \
					"(timestamp, nonce_key_hash)" + \
					" VALUES (%s, %s)",
				[
					timestamp,
					nonce_key_hash
				]
			)
			db_cursor.close()

			db_conn.commit()

			mohawk_sender_ids.append(sender_id)

			return False

		#
		# Subfunction ends
		###################


	if (ba_config.BA_MOHAWK_ENABLED == 1):
		#
		# Try to verify authenticity of the request received --
		# an exception will be raised by Mohawk if there is any
		# problem with it.
		#

		mohawk_sig_res = mohawk.Receiver(
			ba_signature_lookup_sender, 		# Provide callback function to look up caller ID
			http_environ['HTTP_AUTHORIZATION'], 		# HTTP authorization header (only contents of it)
			'http://' + http_environ['HTTP_HOST'] + http_environ['PATH_INFO'], # Construct the URL called
			http_environ['REQUEST_METHOD'], 		# Request method type
			content=data.encode("utf8"), 			# UTF-8 encode the data
			content_type=http_environ['CONTENT_TYPE'],	# Content-type header used
			timestamp_skew_in_seconds=ba_config.BA_MOHAWK_NONCE_EXPIRY,	# Default expiry of nonce tokens
			seen_nonce=ba_signature_nonce_seen	# nonce token checker
		)

	# If verification is OFF, we should FAIL if users DO send
	# Authorization-header -- this is to safeguard against
	# accidentally turning off verification.

	elif (ba_config.BA_MOHAWK_ENABLED == 0):
		assert (http_environ.has_key('HTTP_AUTHORIZATION') != True)

		return None

	return mohawk_sig_res


def ba_acl_check(hawk_id, req_path_valid):
	"""
	Check if caller with Hawk-ID has access to
	the given path indicated by req_path_valid.
	"""

	if (hawk_id == None):
		return False

	# Should never happen - if longer than 1,
	# it indicates that Hawk-signature functions
	# are misbehaving, and adding IDs more than once
	# to the list.

	if (len(hawk_id) != 1):
		return False

	hawk_id = hawk_id[0]


	# Check if the sender is known in the permissions dict -
	# if not, return False; no access then.
	if (ba_config.BA_MOHAWK_PEER_PERMISSIONS.has_key(hawk_id) != True):
		return False

	try:
		# If we find an exact match in the list of allowable endpoints
		# for the hawk_id, return True.

		if (ba_config.BA_MOHAWK_PEER_PERMISSIONS[hawk_id]['endpoints']\
			.index(req_path_valid) >= 0):
			return True

	except:
		# Don't do anything when we get an exception;
		# the dict containing the endpoint ACL exists,
		# but there is no match with the given key.
		# We might find a match in the next step.
		pass

	# Go through list of allowable endpoints for the given
	# sender - check if we find a match with some wildcard.


	for tmp_path_allowable in\
		ba_config.BA_MOHAWK_PEER_PERMISSIONS[hawk_id]['endpoints']:

		if (tmp_path_allowable.find('::0') <= 0):
			continue

		tmp_path_allowable = tmp_path_allowable.replace('::0', '')

		if (req_path_valid.find(tmp_path_allowable) == 0):
			return True

	return False


#
# Functions to handle password-hashing
#

def ba_password_create_salt():
	"""
	Generate 16 bytes of random salt.
	Make sure that the bytes are ASCII encoded,
	and that any special chars are removed (like line-feed).
	"""

	return binascii.b2a_base64(
		os.urandom(16)
	).strip().strip('\n').strip('\r').strip(' ')


def ba_password_hashing(password_str, salt):
	"""
	Create SHA256 hash from given password, using given salt.
	Will return hash as a hex string.
	"""

	dk = pbkdf2_hmac(
		'sha256',
		bytes(password_str),
		bytes(salt),
		(100 * 1000)
	)

	return binascii.hexlify(dk)


def ba_req_input_password_verify(req_password_str, \
		db_password_hashed, db_salt):
	"""
	Verify if given req_password_str matches given db_password_hashed,
	after hashing the first with the given db_salt.
	"""

	return (ba_password_hashing(
		req_password_str,
		db_salt
	) == db_password_hashed)


#
# Deal with HTTP requests from callers.
#

def ba_handler_authenticate(http_environ, start_response, args_extra):
	"""
	Try to authenticate user using JSON request-data.
	"""

	params = http_environ['params']

	# Try to get user input
	try:
		req_username = params['username']
		req_password = params['password']

	except KeyError:
		# That failed, inform user that the resource does not exist.
		return (
			400,
			None,
			{ 'error' : 'Username and/or password missing' }
		)

	#
	# Connect to DB
	#

	try:
		db_conn = ba_db_connect()

	except:
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)

	#
	# Check if username is acceptable
	# by our policy
	#
	# FIXME: Remove, and do only minimal checking.
	#

	if (ba_req_input_check_username(req_username) != True):
		return (
			406,
			None,
			{ 'error': 'Username is not acceptable' }
		)




	# Got some input, try to find a match in the DB.
	try:
		db_cursor = db_conn.cursor()

		# Do not change the order of the fields
		# as this will break the code below where
		# they are referenced.
		db_cursor.execute(
			'SELECT username, password_hashed, salt FROM ' + \
				'accounts WHERE username = %s AND ' + \
				'enabled = 1',
			[req_username]
		)

	except:
		# Inform about DB error
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)

	#
	# Try to fetch something from DB,
	# but maximally one row
	#

	try:
		db_account_info = db_cursor.fetchmany(1)

		# Clean up DB stuff
		db_cursor.close()

	except:
		# Inform about DB error
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)

	#
	# Now we should have gotten something,
	# figure out what to respond with
	#

	if (len(db_account_info) == 1):
		#
		# Check if given password,
		# do match the password originally
		# hashed and saved in the database
		# (and is associated with this account).
		#

		auth_ok = ba_req_input_password_verify(
			req_password,
			db_account_info[0][1],
			db_account_info[0][2]
		)

		if (auth_ok == True):
			# Matches hash, return 200 and JSON-string indicated
			# that the user is authenticated.

			return (
				200,
				None,
				{
					'status': 1,
					'authenticated': auth_ok }
			)

	return (
		403,
		None,
		{ 'error': 'Access denied' }
	)


def ba_handler_account_create(http_environ, start_response, args_extra):
	"""
	Create account, given username and password from JSON request.
	Will do various checks of username and password, and hash
	password.
	"""

	params = http_environ['params']

	# Try to get user input
	try:
		req_username = params['username']
		req_password = params['password']

	except KeyError:
		# That failed, inform user that the resource does not exist.
		return (
			400,
			None,
			{ 'error': 'Username and/or password missing' }
		)

	# Got some input, connect to DB
	try:
		db_conn = ba_db_connect()

	except:
		# Inform about DB error
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)

	#
	# Check if username is acceptable
	# by our policy
	#

	if (ba_req_input_check_username(req_username) != True):
		return (
			406,
			None,
			{ 'error': 'Username is not acceptable' }
		)

	#
	# Check if password is acceptable
	# by our policy
	#

	if (ba_req_input_check_password(req_password) != True):
		return (
			406,
			None,
			{ 'error': 'Password is not acceptable' }
		)


	#
	# New see if account already exists with that username
	# in DB. Do not use enabled parameter,
	# as usernames should be unique.
	#

	try:
		db_cursor = db_conn.cursor()
		db_cursor.execute(
			'SELECT username, password_hashed, salt ' + \
				'FROM accounts WHERE username = %s',
			[req_username]
		)

		db_account_info = db_cursor.fetchmany(1)

		db_cursor.close()

	except:
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)

	# Check if account already exists
	if (len(db_account_info) != 0):
		return (
			422,
			None,
			{ 'error': 'Account exists' }
		)

	# Now create random salt, and create
	# hash of given password using that.
	# Then save the username, hashed password and salt
	# in DB, plus creation timestamp.
	#

	rand_salt = ba_password_create_salt()
	req_password_hashed = ba_password_hashing(req_password, rand_salt)

	try:
		db_cursor = db_conn.cursor()
		db_cursor.execute(
			'INSERT INTO accounts (enabled, ' + \
				'username, password_hashed, salt, ' + \
				'created_at) VALUES (1, %s, %s, %s, %s)',
			[
				req_username,
				req_password_hashed,
				rand_salt,
				int(time.time())
			]
		)

		db_cursor.close()

		# Commit what we just did.
		db_conn.commit()

	except:
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)

	return (
		200,
		None,
			{
				'status': 1,
				'username': req_username
			}
		)


def ba_handler_account_exists(http_environ, start_response, args_extra):
	"""
	Check if accounts exists, given username in JSON request.
	"""

	params = http_environ['params']

	# Try to get user input
	try:
		req_username = params['username']

	except KeyError:
		# That failed, inform user that the resource does not exist.
		return (
			400,
			None,
			{ 'error': 'Username missing' }
		)


	# Got some input, connect to DB
	try:
		db_conn = ba_db_connect()

	except:
		# Inform about DB error
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)


	#
	# Check if username is acceptable
	# by our policy
	#

	if (ba_req_input_check_username(req_username) != True):
		return (
			406,
			None,
			{ 'error': 'Username is not acceptable' }
		)

	#
	# New see if account already exists
	# in DB. Do not consider the enabled
	# field.
	#

	try:
		db_cursor = db_conn.cursor()
		db_cursor.execute(
			'SELECT username, password_hashed, salt ' + \
				'FROM accounts WHERE username = %s',
			[req_username]
		)

		db_account_info = db_cursor.fetchmany(1)

		db_cursor.close()

	except:
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)


	# Check if account already exists
	if (len(db_account_info) == 1):
		return (
			200,
			None,
			{ 'status': 1, 'message': 'Account exists' }
		)

	else:
		return (
			404,
			None,
			{ 'error': 'Account does not exist' }
		)


def ba_handler_account_passwordchange(
		http_environ, start_response, args_extra):
	"""
	Change password for account, given JSON data.
	"""

	params = http_environ['params']

	# Try to get user input
	try:
		req_username = params['username']
		req_password = params['password']

	except KeyError:
		# That failed, inform user that the resource does not exist.
		return (
			400,
			None,
			{ 'error': 'Username and/or password missing' }
		)


	# Got some input, connect to DB
	try:
		db_conn = ba_db_connect()

	except:
		# Inform about DB error
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)


	#
	# Check if username is acceptable
	# by our policy
	#

	if (ba_req_input_check_username(req_username) != True):
		return (
			406,
			None,
			{ 'error': 'Username is not acceptable' }
		)


	#
	# Check if password is acceptable
	# by our policy
	#

	if (ba_req_input_check_password(req_password) != True):
		return (
			406,
			None,
			{ 'error': 'Password is not acceptable' }
		)


	#
	# New see if account exists
	# in DB.
	#

	try:
		db_cursor = db_conn.cursor()
		db_cursor.execute(
			'SELECT username, password_hashed, salt ' + \
				'FROM accounts WHERE username = %s',
			[req_username]
		)

		db_account_info = db_cursor.fetchmany(1)

		db_cursor.close()

	except:
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)


	# Check if account already exists
	if (len(db_account_info) == 0):
		return (
			404,
			None,
			{ 'error': 'Account does not exist' }
		)


	#
	# Try to actually change password of account.
	#

	timestamp_now = int(time.time())
	rand_salt = ba_password_create_salt()
	req_password_hashed = ba_password_hashing(req_password, rand_salt)

	try:
		db_cursor = db_conn.cursor()
		db_cursor.execute(
			'UPDATE accounts SET password_hashed = %s, salt = %s, ' + \
				'updated_at = %s WHERE username = %s',
			[
				req_password_hashed,
				rand_salt,
				timestamp_now,
				req_username
			]
		)

		db_cursor.close()
		db_conn.commit()

	except:
		return (
			500,
			None,
			{ 'error': 'Account-information could not be updated' }
		)

	return (
		200,
		None,
		{
			'status': 1,
			'message': 'Updated password'
		}
	)


def ba_handler_account_enable(http_environ, start_response, args_extra):
	""" Enable account. Calls another function to perform the operation. """
	return ba_handler_account_enable_or_disable(
		http_environ,
		start_response,
		1,
		args_extra
	)

def ba_handler_account_disable(http_environ, start_response, args_extra):
	""" Disable account. Calls another function to perform the operation. """
	return ba_handler_account_enable_or_disable(
		http_environ,
		start_response,
		0,
		args_extra
	)

def ba_handler_account_enable_or_disable(
		http_environ, start_response, enable_account, args_extra):
	"""
	Disable or enable specified account.
	"""

	params = http_environ['params']

	# Try to get user input
	try:
		req_username = params['username']

	except KeyError:
		# That failed, inform user that the resource does not exist.
		return (
			400,
			None,
			{ 'error': 'Username missing' }
		)

	# Got some input, connect to DB
	try:
		db_conn = ba_db_connect()

	except:
		# Inform about DB error
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)


	#
	# Check if username is acceptable
	# by our policy
	#

	if (ba_req_input_check_username(req_username) != True):
		return (
			406,
			None,
			{ 'error': 'Username is not acceptable' }
		)



	#
	# Check if account exists
	#

	try:
		db_cursor = db_conn.cursor()
		db_cursor.execute(
			'SELECT username FROM accounts WHERE username = %s',
			[req_username]
		)

		db_account_info = db_cursor.fetchmany(1)

		db_cursor.close()

	except:
		return (
			500,
			None,
			{ 'error': 'Database communication error' }
		)

	if (len(db_account_info) != 1):
		return (
			404,
			None,
			{ 'error': 'Account does not exist' }
		)

	#
	# Ok, account exists, then enable or disable it
	#

	timestamp_now = int(time.time())

	try:
		db_cursor = db_conn.cursor()
		db_cursor.execute(
			'UPDATE accounts SET enabled = %s, ' + \
				' updated_at = %s WHERE username = %s',
			[
				enable_account,
				timestamp_now,
				req_username
			]
		)
		db_cursor.close()

		db_conn.commit()

	except:
		return (
			500,
			None,
			{ 'error': 'Account-information could not be updated' }
		)

	return (
		200,
		None,
		{
			'status': 1,
			'message': 'Account ' + \
				('enabled' \
					if enable_account == 1 \
					else 'disabled'
				)
		}
	)

def ba_handler_service_health(http_environ, start_response, args_extra):
	"""
	Handle requests for health-related information.
	This function will try to connect to DB, and issue
	a SQL query that should work, no matter how much
	data has been collected. The point is to check
	connectivity.
	"""

	try:
		db_conn = ba_db_connect()

		db_cursor = db_conn.cursor()
		db_cursor.execute("SHOW CREATE TABLE accounts")
		db_tableinfo = db_cursor.fetchall()

		if (len(db_tableinfo) == 0):
			assert False, "DB communication error"

		db_conn.close()

		return (
			200,
			None,
			{ 'status': 1 }
		)

	except:
		return (
			500,
			None,
			{ 'status': 0 }
		)


def ba_handler_options(http_environ, start_response, url_methods_supported):
	resp_headers_extra = [
		( 'Allow', url_methods_supported )
	]

	return (
		200,
		resp_headers_extra,
		''
	)

def ba_dispatcher_init():
	dispatcher = BAPathDispatcher()

	dispatcher.register(
		'POST',
		'/v1/account/create',
		ba_handler_account_create
	)
	dispatcher.register(
		'OPTIONS',
		'/v1/account/create',
		ba_handler_options,
		'POST,OPTIONS'
	)


	dispatcher.register(
		'PUT',
		'/v1/account/passwordchange',
		ba_handler_account_passwordchange
	)
	dispatcher.register(
		'OPTIONS',
		'/v1/account/passwordchange',
		ba_handler_options,
		'PUT,OPTIONS'
	)


	dispatcher.register(
		'POST',
		'/v1/account/authenticate',
		ba_handler_authenticate
	)
	dispatcher.register(
		'OPTIONS',
		'/v1/account/authenticate',
		ba_handler_options,
		'POST,OPTIONS'
	)


	dispatcher.register(
		'GET',
		'/v1/account/exists',
		ba_handler_account_exists
	)
	dispatcher.register(
		'OPTIONS',
		'/v1/account/exists',
		ba_handler_options,
		'GET,OPTIONS'
	)


	dispatcher.register(
		'PUT',
		'/v1/account/disable',
		ba_handler_account_disable
	)
	dispatcher.register(
		'OPTIONS',
		'/v1/account/disable',
		ba_handler_options,
		'PUT,OPTIONS'
	)


	dispatcher.register(
		'PUT',
		'/v1/account/enable',
		ba_handler_account_enable
	)
	dispatcher.register(
		'OPTIONS',
		'/v1/account/enable',
		ba_handler_options,
		'PUT,OPTIONS'
	)


	dispatcher.register(
		'GET',
		'/v1/service/health',
		ba_handler_service_health
	)
	dispatcher.register(
		'OPTIONS',
		'/v1/service/health',
		ba_handler_options,
		'GET,OPTIONS'
	)


	return dispatcher

