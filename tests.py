#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import mohawk
import json
import pprint
import tempfile
import time
import os


def dummy_call_func1():
	return True

def dummy_call_func2():
	return False


class http_server_emulator():
	resp_code 	= None
	headers		= None
	
	def getinfo(self):
		return (self.resp_code, self.headers)

	def __call__(self, resp_code, headers):
		self.headers = headers
		self.resp_code = resp_code

		return True

class http_client_emulator():
	def request_generate(self, req_method, req_host, req_path, req_headers_extra, req_data):
		"""
		Emulate the incoming data from webserver,
		make PathDispatcher handle it, and then
		return the result.
		"""

		http_input_file_info = tempfile.mkstemp()
                
		req_data_json = json.dumps(req_data)

		f_http_input_file = http_input_file_info[0]

		f_http_input_file = open(http_input_file_info[1], 'w')

		if (req_method == 'POST') or (req_method == 'PUT'):
			f_http_input_file.write(req_data_json)
			req_content_type = 'application/json'
			req_query_string = ''

		elif (req_method == 'GET'):
			f_http_input_file.write('')
			req_content_type = 'text/plain'
			req_query_string = ''

			req_data_key_cnt = 0

			for req_data_key in req_data.keys():
				if (len(req_query_string) > 0):
					req_query_string += "&"

				req_query_string += req_data_key + "=" + req_data[req_data_key]

				req_data_key_cnt += 1


		f_http_input_file.close()


		f_http_input_file = open(http_input_file_info[1], 'r')

		f_dev_null = open('/dev/null', 'w')
                 
		req_headers = {
			'CONTENT_LENGTH': len(req_data_json),
			'CONTENT_TYPE': req_content_type,
			'GATEWAY_INTERFACE': 'CGI/1.1',
			'HTTP_ACCEPT': '*/*',
			'HTTP_HOST': req_host,
			'HTTP_USER_AGENT': 'curl/7.29.0',
			'PATH_INFO': req_path,
			'QUERY_STRING': req_query_string,
			'REMOTE_ADDR': '127.0.0.1',
			'REMOTE_HOST': 'localhost.localdomain',
			'REQUEST_METHOD': req_method,
			'SCRIPT_NAME': '',
			'SERVER_NAME': 'localhost.localdomain',
			'SERVER_PORT': '8080',
			'SERVER_PROTOCOL': 'HTTP/1.1',
			'SERVER_SOFTWARE': 'WSGIServer/0.1 Python/2.7.5',
			'params': {},
			'wsgi.errors': f_dev_null,
			'wsgi.input': f_http_input_file,
			'wsgi.multiprocess': False,
			'wsgi.multithread': True,
			'wsgi.run_once': False,
			'wsgi.url_scheme': 'http',
			'wsgi.version': (1, 0)
		}

		if (req_headers_extra != None):
			req_headers += req_headers_extra

		path_dispatcher = ba_core.BAPathDispatcher()

		path_dispatcher.register(req_method, req_path, self.request_generate_handler, None)

		http_environ = path_dispatcher.__call__(req_headers, dummy_call_func1)

		del(http_environ['wsgi.errors'])
		del(http_environ['wsgi.input'])

		f_http_input_file.close()
		f_dev_null.close()

		os.close(http_input_file_info[0])
		os.remove(http_input_file_info[1])
		
		return (http_environ, http_environ['params'])

	def request_generate_handler(self, http_environ, start_response, args_extra):
		return http_environ


class TestPathDispatcher(unittest.TestCase):
	test_call_json_res = {
		'__test_call_json_handler_second_called' : False
	}
	
	test_call_text_plain_res = {
		'__test_call_text_plain_handler_second_called' : False
	}

	test_call_form_urlencoded_res = {
		'__test_call_form_urlencoded_handler_second_called' : False
	}

	test_call_404_res = {
		'__test_call_404_handler_second_called' : False
	}



	def test_register(self):
		path_dispatcher = ba_core.BAPathDispatcher()

		path_dispatcher.register('PUT', '/v1/account/path1', dummy_call_func1, [ 'somestring1' ])
		path_dispatcher.register('GET', '/v1/account/path1', dummy_call_func2, [ 'somestring2' ])
		path_dispatcher.register('GET', '/v1/account/path2', dummy_call_func2, [ 'somestring3' ])

		self.assertEqual(path_dispatcher.pathmap, 
			{
				('put', '/v1/account/path1'): { 'handler': dummy_call_func1, 
						'args_extra' : [ 'somestring1' ] },
				('get', '/v1/account/path1'): { 'handler': dummy_call_func2, 
						'args_extra' : [ 'somestring2' ] },
				('get', '/v1/account/path2'): { 'handler': dummy_call_func2, 
						'args_extra' : [ 'somestring3' ] }
			}
		)


	def test_call_json(self):

		#
		# Emulate HTTP request structures
		#

		http_input_file_info = tempfile.mkstemp()
		f_http_input_file = open(http_input_file_info[1], 'w')
		f_http_input_file.write('{"username":"myuser","password":"mypass"}')
		f_http_input_file.close()

		f_http_input_file = open(http_input_file_info[1], 'r')
		
		f_dev_null = open('/dev/null', 'w')

		http_headers = {
			'CONTENT_LENGTH': '41',
			'CONTENT_TYPE': 'application/json',
			'GATEWAY_INTERFACE': 'CGI/1.1',
			'HTTP_ACCEPT': '*/*',
			'HTTP_HOST': '127.0.0.1:8080',
			'HTTP_USER_AGENT': 'curl/7.29.0',
			'PATH_INFO': '/v1/account/create',
			'QUERY_STRING': '',
			'REMOTE_ADDR': '127.0.0.1',
			'REMOTE_HOST': 'localhost.localdomain',
			'REQUEST_METHOD': 'POST',
			'SCRIPT_NAME': '',
			'SERVER_NAME': 'localhost.localdomain',
			'SERVER_PORT': '8080',
			'SERVER_PROTOCOL': 'HTTP/1.1',
			'SERVER_SOFTWARE': 'WSGIServer/0.1 Python/2.7.5',
			'params': {},
			'wsgi.errors': f_dev_null,
			'wsgi.input': f_http_input_file,
			'wsgi.multiprocess': False,
			'wsgi.multithread': True,
			'wsgi.run_once': False,
			'wsgi.url_scheme': 'http',
			'wsgi.version': (1, 0)
		}

		path_dispatcher = ba_core.BAPathDispatcher()
		path_dispatcher.register('POST', '/v1/account/create', self.__test_call_json_handler_main, None)
		path_dispatcher.register('POST', '/v1/account/create_not_called', self.__test_call_json_handler_second, None)
		path_dispatcher.__call__(http_headers, self.__test_call_json_handler_main)

		#
		# Close temporary file and remove it.
		#
	
		f_http_input_file.close()	
		os.remove(http_input_file_info[1])

		self.assertEqual(self.test_call_json_res, 
			{ 
				'http_environ' : http_headers,
				'args_extra' : None,
				'__test_call_json_handler_second_called' : False
			}
		)

		self.assertEqual(self.test_call_json_res['http_environ']['params'], { "username": "myuser", "password": "mypass" })	

		self.assertEqual(self.test_call_json_res['http_environ']['CONTENT_TYPE'], 'application/json')
	
		return False

	def __test_call_json_handler_main(self, http_environ, start_response, args_extra):
		self.test_call_json_res['http_environ'] = http_environ
		self.test_call_json_res['args_extra'] = args_extra

		return True

	def __test_call_json_handler_second(self, http_environ, start_response, args_extra):
		self.test_call_json_res = { 
			'__test_call_json_handler_second_called': True 
		}

		return True

	
	def test_call_text_plain(self):
		"""
		Test request with text/plain content type
		"""

		#
		# Emulate HTTP request structures
		#

		http_input_file_info = tempfile.mkstemp()
		f_http_input_file = open(http_input_file_info[1], 'w')
		f_http_input_file.write('')
		f_http_input_file.close()

		f_http_input_file = open(http_input_file_info[1], 'r')
		
		f_dev_null = open('/dev/null', 'w')

		http_headers = {
			'CONTENT_LENGTH': '0',
			'CONTENT_TYPE': 'text/plain',
			'GATEWAY_INTERFACE': 'CGI/1.1',
			'HTTP_ACCEPT': '*/*',
			'HTTP_HOST': '127.0.0.1:8080',
			'HTTP_USER_AGENT': 'curl/7.29.0',
			'PATH_INFO': '/v1/account/create',
			'QUERY_STRING': 'username=myotheruser&password=myotherpass',
			'REMOTE_ADDR': '127.0.0.1',
			'REMOTE_HOST': 'localhost.localdomain',
			'REQUEST_METHOD': 'GET',
			'SCRIPT_NAME': '',
			'SERVER_NAME': 'localhost.localdomain',
			'SERVER_PORT': '8080',
			'SERVER_PROTOCOL': 'HTTP/1.1',
			'SERVER_SOFTWARE': 'WSGIServer/0.1 Python/2.7.5',
			'params': {},
			'wsgi.errors': f_dev_null,
			'wsgi.input': f_http_input_file,
			'wsgi.multiprocess': False,
			'wsgi.multithread': True,
			'wsgi.run_once': False,
			'wsgi.url_scheme': 'http',
			'wsgi.version': (1, 0)
		}

		path_dispatcher = ba_core.BAPathDispatcher()
		path_dispatcher.register('GET', '/v1/account/create', self.__test_call_text_plain_handler_main, None)
		path_dispatcher.register('GET', '/v1/account/create_not_called', self.__test_call_text_plain_handler_second, None)
		path_dispatcher.__call__(http_headers, self.__test_call_text_plain_handler_main)

		#
		# Close temporary file and remove it.
		#
	
		f_http_input_file.close()	
		os.remove(http_input_file_info[1])

		self.assertEqual(self.test_call_text_plain_res, 
			{ 
				'http_environ' : http_headers,
				'args_extra' : None,
				'__test_call_text_plain_handler_second_called' : False
			}
		)

		self.assertEqual(self.test_call_text_plain_res['http_environ']['params'], 
			{ 
				"username": "myotheruser", 
				"password": "myotherpass" 
			}
		)

		self.assertEqual(self.test_call_text_plain_res['http_environ']['CONTENT_TYPE'], 'text/plain')
	
		return False

	def __test_call_text_plain_handler_main(self, http_environ, start_response, args_extra):
		self.test_call_text_plain_res['http_environ'] = http_environ
		self.test_call_text_plain_res['args_extra'] = args_extra

		return True

	def __test_call_text_plain_handler_second(self, http_environ, start_response, args_extra):
		self.test_call_text_plain_res = { 
			'__test_call_text_plain_handler_second_called': True 
		}

		return True



	def test_call_form_urlencoded(self):
		"""
		Test request with text/plain content type
		"""

		#
		# Emulate HTTP request structures
		#

		http_input_file_info = tempfile.mkstemp()
		f_http_input_file = open(http_input_file_info[1], 'w')
		f_http_input_file.write('username=myyetotheruser&password=myyetotherpass')
		f_http_input_file.close()

		f_http_input_file = open(http_input_file_info[1], 'r')
		
		f_dev_null = open('/dev/null', 'w')

		http_headers = {
			'CONTENT_LENGTH': '47',
			'CONTENT_TYPE': 'application/x-www-form-urlencoded',
			'GATEWAY_INTERFACE': 'CGI/1.1',
			'HTTP_ACCEPT': '*/*',
			'HTTP_HOST': '127.0.0.1:8080',
			'HTTP_USER_AGENT': 'curl/7.29.0',
			'PATH_INFO': '/v1/account/create',
			'QUERY_STRING': '',
			'REMOTE_ADDR': '127.0.0.1',
			'REMOTE_HOST': 'localhost.localdomain',
			'REQUEST_METHOD': 'POST',
			'SCRIPT_NAME': '',
			'SERVER_NAME': 'localhost.localdomain',
			'SERVER_PORT': '8080',
			'SERVER_PROTOCOL': 'HTTP/1.1',
			'SERVER_SOFTWARE': 'WSGIServer/0.1 Python/2.7.5',
			'params': {},
			'wsgi.errors': f_dev_null,
			'wsgi.input': f_http_input_file,
			'wsgi.multiprocess': False,
			'wsgi.multithread': True,
			'wsgi.run_once': False,
			'wsgi.url_scheme': 'http',
			'wsgi.version': (1, 0)
		}

		http_server_emulator_instance = http_server_emulator()

		path_dispatcher = ba_core.BAPathDispatcher()
		path_dispatcher.register('POST', '/v1/account/create', self.__test_call_form_urlencoded_handler_main, None)
		path_dispatcher.register('POST', '/v1/account/create_not_called', self.__test_call_form_urlencoded_handler_second, None)
		path_dispatcher.__call__(http_headers, http_server_emulator_instance)

		#
		# Close temporary file and remove it.
		#
	
		f_http_input_file.close()	
		os.remove(http_input_file_info[1])

		self.assertEqual(self.test_call_form_urlencoded_res, 
			{ 
				'http_environ' : http_headers,
				'args_extra' : None,
				'__test_call_form_urlencoded_handler_second_called' : False
			}
		)

		self.assertEqual(self.test_call_form_urlencoded_res['http_environ']['params'], 
			{ 
				"username": "myyetotheruser", 
				"password": "myyetotherpass" 
			}
		)

		self.assertEqual(self.test_call_form_urlencoded_res['http_environ']['CONTENT_TYPE'], 'application/x-www-form-urlencoded')
	
		return False

	def __test_call_form_urlencoded_handler_main(self, http_environ, start_response, args_extra):
		self.test_call_form_urlencoded_res['http_environ'] = http_environ
		self.test_call_form_urlencoded_res['args_extra'] = args_extra

		return True

	def __test_call_form_urlencoded_handler_second(self, http_environ, start_response, args_extra):
		self.test_call_form_urlencoded_res = { 
			'__test_call_form_urlencoded_handler_second_called': True 
		}

		return True



	def test_call_404(self):
		"""
		Test request with non-existing path (i.e. 404 handler).
		"""

		#
		# Emulate HTTP request structures
		#

		http_input_file_info = tempfile.mkstemp()
		f_http_input_file = open(http_input_file_info[1], 'w')
		f_http_input_file.write('')
		f_http_input_file.close()

		f_http_input_file = open(http_input_file_info[1], 'r')
		
		f_dev_null = open('/dev/null', 'w')

		http_headers = {
			'CONTENT_LENGTH': '0',
			'CONTENT_TYPE': 'text/plain',
			'GATEWAY_INTERFACE': 'CGI/1.1',
			'HTTP_ACCEPT': '*/*',
			'HTTP_HOST': '127.0.0.1:8080',
			'HTTP_USER_AGENT': 'curl/7.29.0',
			'PATH_INFO': '/v1/account/create',
			'QUERY_STRING': 'username=myotheruser&password=myotherpass',
			'REMOTE_ADDR': '127.0.0.1',
			'REMOTE_HOST': 'localhost.localdomain',
			'REQUEST_METHOD': 'POST',			# NOTE: No GET handler matching this path
			'SCRIPT_NAME': '',
			'SERVER_NAME': 'localhost.localdomain',
			'SERVER_PORT': '8080',
			'SERVER_PROTOCOL': 'HTTP/1.1',
			'SERVER_SOFTWARE': 'WSGIServer/0.1 Python/2.7.5',
			'params': {},
			'wsgi.errors': f_dev_null,
			'wsgi.input': f_http_input_file,
			'wsgi.multiprocess': False,
			'wsgi.multithread': True,
			'wsgi.run_once': False,
			'wsgi.url_scheme': 'http',
			'wsgi.version': (1, 0)
		}

		http_server_emulator_instance = http_server_emulator()

		path_dispatcher = ba_core.BAPathDispatcher()
		path_dispatcher.register('GET', '/v1/account/create', self.__test_call_404_handler_main, None)
		path_dispatcher.register('GET', '/v1/account/create_not_called', self.__test_call_404_handler_second, None)
		path_dispatcher.__call__(http_headers, http_server_emulator_instance)


		#
		# Close temporary file and remove it.
		#
	
		f_http_input_file.close()	
		os.remove(http_input_file_info[1])

		self.assertEqual(self.test_call_404_res, 
			{ 
				'__test_call_404_handler_second_called' : False
			}
		)

		self.assertEqual(http_server_emulator_instance.getinfo(),       ('404 Not Found',
			[ ('Content-type', 'application/json'),
				('Cache-Control', 'no-cache'),
				('Pragma', 'no-cache')
			]
		))

		return False

	def __test_call_404_handler_main(self, http_environ, start_response, args_extra):
		self.test_call_404_res['http_environ'] = http_environ
		self.test_call_404_res['args_extra'] = args_extra

		return True

	def __test_call_404_handler_second(self, http_environ, start_response, args_extra):
		self.test_call_40_res = { 
			'__test_call_404_handler_second_called': True 
		}

		return True


class TestHttpRespMethods(unittest.TestCase):
	def test_ba_http_resp_404(self):
		http_server_emulator_instance = http_server_emulator()
		http_resp_body = ba_core.ba_http_resp_404(None, http_server_emulator_instance, None)

		self.assertEqual(json.loads(http_resp_body), json.loads('{"error": "Not found"}'))
		self.assertEqual(http_server_emulator_instance.getinfo(),	('404 Not Found', 
			[ 
				('Content-type', 'application/json'), 
				('Cache-Control', 'no-cache'), 
				('Pragma', 'no-cache')
			]
		))

	def test_ba_http_resp_json_200a(self):
		http_server_emulator_instance = http_server_emulator()

		http_resp_body = ba_core.ba_http_resp_json(None, http_server_emulator_instance, 200, None, 
			{ 
				"somefield1":"somedata1", "somefield2":"somedata2" 
			}
		)

		self.assertEqual(http_server_emulator_instance.resp_code, "200 OK")
		self.assertEqual(http_server_emulator_instance.headers, 
			[
				('Content-type', 'application/json'),
				('Cache-Control', 'no-cache'),
				('Pragma', 'no-cache')
			]
		)

		self.assertEqual(json.loads(http_resp_body), json.loads('{"somefield2": "somedata2", "somefield1": "somedata1"}'))

	def test_ba_http_resp_json_200b(self):
		http_server_emulator_instance = http_server_emulator()

		http_resp_body = ba_core.ba_http_resp_json(None, http_server_emulator_instance, 200, [ ('Header1Field', 'Header1Value') ], 
			{ 
				"somefield1":"somedata1", "somefield2":"somedata2" 
			}
		)

		self.assertEqual(http_server_emulator_instance.resp_code, "200 OK")
		self.assertEqual(http_server_emulator_instance.headers, 
			[
				('Content-type', 'application/json'),
				('Cache-Control', 'no-cache'),
				('Pragma', 'no-cache'),
				('Header1Field', 'Header1Value'),
			]
		)

		self.assertEqual(json.loads(http_resp_body), json.loads('{"somefield2": "somedata2", "somefield1": "somedata1"}'))


	def test_ba_http_resp_json_404a(self):
		http_server_emulator_instance = http_server_emulator()

		http_resp_body = ba_core.ba_http_resp_json(None, http_server_emulator_instance, 404, None, 
			{ 
				"somefield1":"somedata1", "somefield2":"somedata2" 
			}
		)

		self.assertEqual(http_server_emulator_instance.resp_code, "404 Not Found")
		self.assertEqual(http_server_emulator_instance.headers, 
			[
				('Content-type', 'application/json'),
				('Cache-Control', 'no-cache'),
				('Pragma', 'no-cache')
			]
		)

		self.assertEqual(json.loads(http_resp_body), json.loads('{"somefield2": "somedata2", "somefield1": "somedata1"}'))

	def test_ba_http_resp_json_404b(self):
		http_server_emulator_instance = http_server_emulator()

		http_resp_body = ba_core.ba_http_resp_json(None, http_server_emulator_instance, 404, [ ('Header1Field', 'Header1Value') ], 
			{ 
				"somefield1":"somedata1", "somefield2":"somedata2" 
			}
		)

		self.assertEqual(http_server_emulator_instance.resp_code, "404 Not Found")
		self.assertEqual(http_server_emulator_instance.headers, 
			[
				('Content-type', 'application/json'),
				('Cache-Control', 'no-cache'),
				('Pragma', 'no-cache'),
				('Header1Field', 'Header1Value'),
			]
		)

		self.assertEqual(json.loads(http_resp_body), json.loads('{"somefield2": "somedata2", "somefield1": "somedata1"}'))


	def test_ba_http_resp_json_500a(self):
		http_server_emulator_instance = http_server_emulator()

		http_resp_body = ba_core.ba_http_resp_json(None, http_server_emulator_instance, 500, None, 
			{ 
				"somefield1":"somedata1", "somefield2":"somedata2" 
			}
		)

		self.assertEqual(http_server_emulator_instance.resp_code, "500 Error")
		self.assertEqual(http_server_emulator_instance.headers, 
			[
				('Content-type', 'application/json'),
				('Cache-Control', 'no-cache'),
				('Pragma', 'no-cache'),
			]
		)	
	
		self.assertEqual(json.loads(http_resp_body), json.loads('{"somefield2": "somedata2", "somefield1": "somedata1"}'))

	def test_ba_http_resp_json_500b(self):
		http_server_emulator_instance = http_server_emulator()

		http_resp_body = ba_core.ba_http_resp_json(None, http_server_emulator_instance, 500, [ ( 'Header2Field', 'Header2Value' ) ], 
			{ 
				"somefield1":"somedata1", "somefield2":"somedata2" 
			}
		)

		self.assertEqual(http_server_emulator_instance.resp_code, "500 Error")
		self.assertEqual(http_server_emulator_instance.headers, 
			[
				('Content-type', 'application/json'),
				('Cache-Control', 'no-cache'),
				('Pragma', 'no-cache'),
				('Header2Field', 'Header2Value'),
			]
		)

		self.assertEqual(json.loads(http_resp_body), json.loads('{"somefield2": "somedata2", "somefield1": "somedata1"}'))

class TestDBRoutines(unittest.TestCase):
	def test_db_connect(self):
		unittest.ba_db_connect_tested = True

		# Make sure we will be connecting to a test-database
		self.assertEqual(ba_core.BA_DB_NAME.rfind('_test'), len(ba_core.BA_DB_NAME) - len('_test'))
		self.assertEqual(ba_core.BA_DB_NAME.split('_test'), [ ba_core.BA_DB_NAME_NOT_TESTING, '' ])

		db_conn = ba_core.ba_db_connect()

		db_cursor = db_conn.cursor()
		db_cursor.execute("SHOW STATUS LIKE  'Bytes_sent' ")
		db_show_status_info = db_cursor.fetchall()

		self.assertTrue(db_show_status_info[0][1] > 0)

		db_conn.close()

		return True

 	def test_db_table_create(self):
		db_conn = ba_core.ba_db_connect()

		ba_core.ba_db_create_tables()

		db_cursor = db_conn.cursor()
		db_cursor.execute("DESC accounts")

		db_table_info_accounts = db_cursor.fetchall()

		self.assertEqual(db_table_info_accounts[0], ('id', 'bigint(20)', 'NO', 'PRI', None, 'auto_increment'))
		self.assertEqual(db_table_info_accounts[1], ('enabled', 'int(11)', 'NO', '', '0', ''))
		self.assertEqual(db_table_info_accounts[2], ('username', 'varchar(128)', 'NO', 'UNI', None, ''))
		self.assertEqual(db_table_info_accounts[3], ('password_hashed', 'varchar(256)', 'NO', '', None, ''))
		self.assertEqual(db_table_info_accounts[4], ('salt', 'varchar(128)', 'NO', '', None, ''))
		self.assertEqual(db_table_info_accounts[5], ('created_at', 'bigint(20)', 'NO', '', None, ''))
		self.assertEqual(db_table_info_accounts[6], ('updated_at', 'bigint(20)', 'YES', '', None, ''))


		db_cursor = db_conn.cursor()
		db_cursor.execute("DESC nonce")

		db_table_info_nonce = db_cursor.fetchall()

		self.assertEqual(db_table_info_nonce[0], ('id', 'bigint(20)', 'NO', 'PRI', None, 'auto_increment'))
		self.assertEqual(db_table_info_nonce[1], ('nonce_key_hash', 'varchar(64)', 'NO', 'MUL', None, ''))
		self.assertEqual(db_table_info_nonce[2], ('timestamp', 'bigint(20)', 'NO', '', None, ''))

		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE accounts")

		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")
	
		return True

class TestReqInput(unittest.TestCase):
	def test_username(self):
		# These should return 'True'
		self.assertTrue(ba_core.ba_req_input_check_username('johndoe'))
		self.assertTrue(ba_core.ba_req_input_check_username('john'))
		self.assertTrue(ba_core.ba_req_input_check_username('john5000'))
		self.assertTrue(ba_core.ba_req_input_check_username('john9810'))
		self.assertTrue(ba_core.ba_req_input_check_username('john9810'))

		# These should return 'False'
		self.assertFalse(ba_core.ba_req_input_check_username('joe'))
		self.assertFalse(ba_core.ba_req_input_check_username('1joe'))
		self.assertFalse(ba_core.ba_req_input_check_username('1joe50'))
 		self.assertFalse(ba_core.ba_req_input_check_username('johnZ'))
 		self.assertFalse(ba_core.ba_req_input_check_username('johnZAL'))
 		self.assertFalse(ba_core.ba_req_input_check_username(u"johnð"))
 		self.assertFalse(ba_core.ba_req_input_check_username(u"johnæ"))
 		self.assertFalse(ba_core.ba_req_input_check_username(u"johnú1500"))
		self.assertFalse(ba_core.ba_req_input_check_username('27926ba0d1451c9d0f775a' +
			'a28d6de86a0f32852527926ba0d1451c9d0f775aa28d6de86a0f32852527926ba0d' +
			'1451c9d0f775aa28d6de86a0f3285256de86a0f328'))

	def test_password(self):
		self.assertTrue(ba_core.ba_req_input_check_password('YaQ903ENr'))
		self.assertTrue(ba_core.ba_req_input_check_password('YaQ903ENr93838a'))
		self.assertTrue(ba_core.ba_req_input_check_password('YaQ903ENr|'))
		self.assertTrue(ba_core.ba_req_input_check_password('YaQ--903E#Nr!938(3)8a'))
	
	
		# These should return 'False'
		self.assertFalse(ba_core.ba_req_input_check_password('123'))
		self.assertFalse(ba_core.ba_req_input_check_password('123æ'))
		self.assertFalse(ba_core.ba_req_input_check_password(u'ðæ123a'))
		self.assertFalse(ba_core.ba_req_input_check_password('abc123\n'))
		self.assertFalse(ba_core.ba_req_input_check_username(u"johnú1500\n"))
		self.assertFalse(ba_core.ba_req_input_check_password('a694ea4fb0ac52201bba8f3' +
			'f63e20b2f20880f534eac614890f341f01009deb9b7a1475640f1522baf19be568cc' +
			'f45b16fcdface4b7633497343cb'))

class TestMowhak(unittest.TestCase):
	def setUp(self):
		self.db_conn = ba_core.ba_db_connect()

		ba_core.ba_db_create_tables()


	def tearDown(self):
		db_cursor = self.db_conn.cursor()
		db_cursor.execute("DROP TABLE accounts")
                
		db_cursor = self.db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")

		self.db_conn.close()


	def test_signature_lookup_sender(self):

		#
		# This sender_id exists
		#

		self.assertEqual(ba_core.ba_signature_lookup_sender('testing_entry'), 
			ba_core.BA_MOHAWK_SENDERS['testing_entry'])

		
		# These sender_id's do not exist
		#

		with self.assertRaises(LookupError):
			ba_core.ba_signature_lookup_sender(' testing_entry')

		with self.assertRaises(LookupError):
			ba_core.ba_signature_lookup_sender('testing_entry ')

		with self.assertRaises(LookupError):
			ba_core.ba_signature_lookup_sender('testing_Entry')

	def test_ba_signature_mohawk_on_all_ok(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		
		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/account/create'
			req_extra_headers = None
			req_data_orig = { 'username' : 'myuser', 'password': 'mypass' }
			req_data_mohawk_test = "username=" + req_data_orig["username"] + "&" + "password=" + req_data_orig["password"]

			#
			# Simulate http client request and
			# get result 
			#

			(http_environ, http_req_params) = http_client.request_generate(req_method, req_host, req_path, req_extra_headers, req_data_orig)
	
			# Sign the request
			sender = mohawk.Sender(ba_core.ba_signature_lookup_sender('testing_entry'),
				"http://" + req_host + req_path,
				req_method,
				content="username=" + http_req_params["username"] + "&" + "password=" + http_req_params["password"],
				content_type=http_environ['CONTENT_TYPE'])
	
			http_environ['HTTP_AUTHORIZATION'] = sender.request_header	
	
			#
			# Try to validate request using Mohawk
			# 
	
			# Mohawk will throw an exception if validation
			# fails. We do not have to.
			ba_core.ba_signature(self.db_conn, http_environ, req_data_mohawk_test)


	def test_ba_signature_mohawk_on_invalid_http_path(self):
		"""
		Try if validation fails with Mohawk turned on.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)


		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/account/create'
			req_extra_headers = None
			req_data_orig = { 'username' : 'myuser', 'password': 'mypass' }
			req_data_mohawk_test = "username=" + req_data_orig["username"] + "&" + "password=" + req_data_orig["password"]

			#
			# Simulate http client request and
			# get result 
			#

			(http_environ, http_req_params) = http_client.request_generate(req_method, req_host, req_path, req_extra_headers, req_data_orig)
	
			# Sign the request
			sender = mohawk.Sender(ba_core.ba_signature_lookup_sender('testing_entry'),
				"http://" + req_host + req_path + "erronus",
				req_method,
				content="username=" + http_req_params["username"] + "&" + "password=" + http_req_params["password"],
				content_type=http_environ['CONTENT_TYPE'])
	
			http_environ['HTTP_AUTHORIZATION'] = sender.request_header	
	
			#
			# Try to validate request using Mohawk
			# 

			with self.assertRaises(mohawk.exc.MacMismatch):
				# Mohawk will throw an exception if validation
				# fails. We do not have to.
				ba_core.ba_signature(self.db_conn, http_environ, req_data_mohawk_test)


	def test_ba_signature_mohawk_on_injected_data(self):
		"""
		Try if validation fails with Mohawk turned on.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)


		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/account/create'
			req_extra_headers = None
			req_data_orig = { 'username' : 'myuser', 'password': 'mypass' }
			req_data_mohawk_test = "username=mySOMEUSER&" + "password=mySOMEPASSWORD"

			#
			# Simulate http client request and
			# get result 
			#

			(http_environ, http_req_params) = http_client.request_generate(req_method, req_host, req_path, req_extra_headers, req_data_orig)
	
			# Sign the request
			sender = mohawk.Sender(ba_core.ba_signature_lookup_sender('testing_entry'),
				"http://" + req_host + req_path + "",
				req_method,
				content="username=" + http_req_params["username"] + "&" + "password=" + http_req_params["password"],
				content_type=http_environ['CONTENT_TYPE'])
	
			http_environ['HTTP_AUTHORIZATION'] = sender.request_header	
	
			#
			# Try to validate request using Mohawk
			# 

			

			with self.assertRaises(mohawk.exc.MacMismatch):
				# Mohawk will throw an exception if validation
				# fails. We do not have to.
				ba_core.ba_signature(self.db_conn, http_environ, req_data_mohawk_test)

                
	def test_ba_signature_mohawk_on_repeated_token(self):
		"""
		Try if validation fails with Mohawk turned on.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)


		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/account/create'
			req_extra_headers = None
			req_data_orig = { 'username' : 'myuser', 'password': 'mypass' }
			req_data_mohawk_test = "username=" + req_data_orig["username"] + "&" + "password=" + req_data_orig["password"]

			#
			# Simulate http client request and
			# get result 
			#

			(http_environ, http_req_params) = http_client.request_generate(req_method, req_host, req_path, req_extra_headers, req_data_orig)
	
			# Sign the request
			sender = mohawk.Sender(ba_core.ba_signature_lookup_sender('testing_entry'),
				"http://" + req_host + req_path + "",
				req_method,
				content="username=" + http_req_params["username"] + "&" + "password=" + http_req_params["password"],
				content_type=http_environ['CONTENT_TYPE'])
	
			http_environ['HTTP_AUTHORIZATION'] = sender.request_header
	
			#
			# Try to validate request using Mohawk
			# 
	
			# Mohawk will throw an exception if validation
			# fails. We do not have to.
			ba_core.ba_signature(self.db_conn, http_environ, req_data_mohawk_test)

			# Try repeatedly to re-use token -- should not work
			for x in range(0, 10):
				with self.assertRaises(mohawk.exc.AlreadyProcessed):
					ba_core.ba_signature(self.db_conn, http_environ, req_data_mohawk_test)


	def test_ba_signature_mohawk_off_all_ok(self):
		self.assertTrue(unittest.ba_db_connect_tested)


		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/account/create'
			req_extra_headers = None
			req_data_orig = { 'username' : 'myuser', 'password': 'mypass' }
			req_data_mohawk_test = "username=" + req_data_orig["username"] + "&" + "password=" + req_data_orig["password"]

			#
			# Simulate http client request and
			# get result 
			#

			(http_environ, http_req_params) = http_client.request_generate(req_method, req_host, req_path, req_extra_headers, req_data_orig)
	
	
			#
			# Try to validate request using Mohawk
			# 

			ba_core.BA_MOHAWK_ENABLED = 0

			# Mohawk will throw an exception if validation
			# fails. We do not have to.
			ba_core.ba_signature(self.db_conn, http_environ, req_data_mohawk_test)

			ba_core.BA_MOHAWK_ENABLED = 1


	def test_ba_signature_mohawk_off_auth_headers_sent(self):
		self.assertTrue(unittest.ba_db_connect_tested)


		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/account/create'
			req_extra_headers = None
			req_data_orig = { 'username' : 'myuser', 'password': 'mypass' }
			req_data_mohawk_test = "username=" + req_data_orig["username"] + "&" + "password=" + req_data_orig["password"]

			#
			# Simulate http client request and
			# get result 
			#

			(http_environ, http_req_params) = http_client.request_generate(req_method, req_host, req_path, req_extra_headers, req_data_orig)

			# Sign the request
			sender = mohawk.Sender(ba_core.ba_signature_lookup_sender('testing_entry'),
				"http://" + req_host + req_path + "",
				req_method,
				content="username=" + http_req_params["username"] + "&" + "password=" + http_req_params["password"],
				content_type=http_environ['CONTENT_TYPE'])
	
			http_environ['HTTP_AUTHORIZATION'] = sender.request_header

			ba_core.BA_MOHAWK_ENABLED = 0
	
			#
			# Try to validate request  
			# 

			with self.assertRaises(AssertionError):
				ba_core.ba_signature(self.db_conn, http_environ, req_data_mohawk_test)

			ba_core.BA_MOHAWK_ENABLED = 1
 

class TestPasswordFuncs(unittest.TestCase):
	def test_ba_password_create_salt(self):
		for i in range(0, 250):

			salt = ba_core.ba_password_create_salt()
			
			salt.encode("ascii")

			for salt_pos in range(0, len(salt)):
				assert salt[salt_pos] != ' '
				assert salt[salt_pos] != '\r'
				assert salt[salt_pos] != '\n'

	def test_ba_password_hashing(self):
		for i in range(0, 10):
			self.assertEqual(
				ba_core.ba_password_hashing(
					'1dd57b94b4d31c0456589ae5ca7f5fcc1c09d1bec0d386c08f9ef8447901cc2d', 
					'giCLXllkoQTEyIg1M+XmMA=='),
				'02ec7fc293326887397dd8f1386e959784dd941cc690952db5f4d71c97960ce8'
			)

	def test_ba_req_input_password_verify(self):
		self.assertEqual(
			ba_core.ba_req_input_password_verify(
				'1dd57b94b4d31c0456589ae5ca7f5fcc1c09d1bec0d386c08f9ef8447901cc2d', 
				'02ec7fc293326887397dd8f1386e959784dd941cc690952db5f4d71c97960ce8', 
				'giCLXllkoQTEyIg1M+XmMA=='
			), 
			True
		)

		self.assertEqual(
			ba_core.ba_req_input_password_verify(
				'1dd57b94b4d31c0456589ae5ca7f5fcc1c09d1bec0d386XXXXXXXXXXXXX', 
				'02ec7fc293326887397dd8f1386e959784dd941cc690952db5f4d71c97960ce8', 
				'giCLXllkoQTEyIg1M+XmMA=='
			), 
			False
		)

		self.assertEqual(
			ba_core.ba_req_input_password_verify(
				'1dd57b94b4d31c0456589ae5ca7f5fcc1c09d1bec0d386c08f9ef8447901cc2d', 
				'02ec7fc293326887397dd8f1386e959784dd941cc690952dXXXXXXXXXXXX', 
				'giCLXllkoQTEyIg1M+XmMA=='
			), 
			False
		)

		self.assertEqual(
			ba_core.ba_req_input_password_verify(
				'1dd57b94b4d31c0456589ae5ca7f5fcc1c09d1bec0d386c08f9ef8447901cc2d', 
				'02ec7fc293326887397dd8f1386e959784dd941cc690952db5f4d71c97960ce8',
				'giCLXllkoQTEyIg1M=='
			), 
			False
		)

class TestHttpHandlers(unittest.TestCase):
	db_conn = None

	def setUp(self):
		"""
		Set settings-variables, connect to DB, create tables
		that we might need.
		"""

		ba_core.BA_DB_NAME = ba_core.ORIG_CONFIG_BA_DB_NAME 
		ba_core.BA_MOHAWK_ENABLED = ba_core.ORIG_CONFIG_BA_MOHAWK_ENABLED
		ba_core.BA_MOHAWK_SENDERS = ba_core.ORIG_CONFIG_BA_MOHAWK_SENDERS 

		# Make sure all tables exist
		ba_core.ba_db_create_tables()

		#
		# Create some totally unrelated accounts 
		# that we do not want to be touched
		#

		for user_cnt in range(0, 5):
			self.__account_create('unrelateduser' + str(user_cnt), 'unrelated_pass_' + str(user_cnt))

		self.db_conn = ba_core.ba_db_connect()


	def tearDown(self):
		"""
		Remove all tables that we might have created.
		"""

		db_cursor = self.db_conn.cursor()
		db_cursor.execute("DROP TABLE accounts")

		db_cursor = self.db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")

		self.db_conn.commit()
		self.db_conn.close()

		self.db_conn = None


	def __account_create(self, username, password):
		"""
		Create a new account. This is done by
		using the API.
		"""

		(http_server, http_client, http_req, http_req_params, http_environ,
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', username, password)

		ba_core.ba_handler_account_create(http_environ, http_server, None)


	def __account_dump_all(self, exclude = None):
		"""
		Dump accounts-table from DB. This is mainly
		for data-integrity checks.
		"""

		db_cursor = self.db_conn.cursor()

		if (exclude == None):
			db_cursor.execute("SELECT id, enabled, username, password_hashed, salt, \
				created_at, updated_at FROM accounts ORDER BY username")

		else:
			db_cursor.execute("SELECT id, enabled, username, password_hashed, salt, \
				created_at, updated_at FROM accounts WHERE username != %s ORDER BY username")

		db_accounts_info = db_cursor.fetchall()

		db_cursor.close()

		self.db_conn.rollback()

		return db_accounts_info


	def __gen_basic_http_req(self, path = None, method = None, username = None, password = None, mohawk_sender_id = None):
		"""
		Simulate generation of HTTP request, as WSGI-compliant server would
		return to us (i.e. data). Also sign it using Mohawk.
		"""

		if (method == None):
			method = 'POST'

		if (mohawk_sender_id == None):
			mohawk_sender_id = 'testing_entry'		

		http_server = http_server_emulator()
		http_client = http_client_emulator()

		http_req = {
			'method': method,
			'host': 'localhost',
		}

		if (path != None):
			http_req['path'] = path

		http_req_params = { 
		}

		if (username is not None):
			http_req_params['username'] = username

		if (password is not None):
			http_req_params['password'] = password


		(http_parsed_environ, http_parsed_params) = http_client.request_generate(http_req['method'], http_req['host'], http_req['path'], 
			None, http_req_params)


		# Sign the request

		mohawk_sender_data = {
			'content': ''
		}

		if (http_parsed_params.has_key('username')):
			mohawk_sender_data['content'] += 'username=' + http_parsed_params['username']
	
		if (http_parsed_params.has_key('password')):
			if (len(mohawk_sender_data['content']) > 0):
				mohawk_sender_data['content'] += '&'

			mohawk_sender_data['content'] += 'password=' + http_parsed_params['password']

		if (ba_core.BA_MOHAWK_ENABLED == 1):
			mohawk_sender_sig = mohawk.Sender(ba_core.ba_signature_lookup_sender(mohawk_sender_id),
				"http://" + http_req['host'] + http_req['path'] + "",
				http_req['method'],
				content=mohawk_sender_data['content'],
				content_type=http_parsed_environ['CONTENT_TYPE'])

			http_parsed_environ['HTTP_AUTHORIZATION'] = mohawk_sender_sig.request_header

		elif (ba_core.BA_MOHAWK_ENABLED == 0):
			mohawk_sender_sig = None

		return (http_server, http_client, http_req, http_req_params, http_parsed_environ, mohawk_sender_sig)


	def test_ba_handler_authenticate_no_sig(self):
		"""
		Create accounts. Then try to authenticate using correct username & password,
		but with no HTTP Authoriziation (Hawk) header. Should result in an error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create("myuser", "mypass")

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 'myuser', 'mypass')


		del(http_environ['HTTP_AUTHORIZATION'])

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_authenticate_corrupt_sig(self):
		"""
		Create valid user & password. Then try to authenticate with a
		request that has invalid Hawk header.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create("myuser", "mypass")

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 'myuser', 'mypass')


		# Maximize likelyhood of replacing some character(s)
		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("a", "s").replace("b", "q").replace("c", "d").replace("d", "e").replace("e", "E").\
			replace("g", "e").replace("h", "e").replace("i", "e").replace("j", "e").replace("k", "e")

		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("A", "s").replace("B", "q").replace("C", "d").replace("D", "e").replace("E", "e").\
			replace("G", "s").replace("H", "q").replace("I", "d").replace("J", "e").replace("K", "e")

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_authenticate_corrupt_username(self):
		"""
		Create username & password, emulate request, and sign it. Then corrupt
		the username sent. Should result in an error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('myusername', 'mypassword')

		db_account_state_before = self.__account_dump_all()

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'myusername', 'mypassword')


		http_environ['params']['username'] = "yetanotherusername"

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		                
		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)
		

	def test_ba_handler_authenticate_corrupt_password(self):
		"""
		Create username & password, emulate request, and sign it. Then corrupt
		the password sent. Should result in an error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('myusername', 'mypassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST',
			'myusername', 'mypassword')


		http_environ['params']['password'] = "yetanotherpassword"

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_authenticate_sig_ok(self):
		"""
		Do not create an account, but try to authenticate with an account
		that does not exist. Should result in a 403 Access Denied error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

                db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST',
			'myusername', 'mypassword')


		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		# Normal error: The account does not exist
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Access denied"}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_authenticate_ok(self):
		"""
		Create a series of acccounts. Then try to authenticate against these
		accounts, with a valid password, using valid Hawk-signature. Should succeed.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		#
		# Do this a few times, just
		# to make sure all the DB-work
		# is good -- especially the Mohawk stuff.
		#

		for i in range(0, 10):
			self.__account_create("someuser" + str(i), "otherPassWord")

		# For data-integrity checks
		db_account_state_before = self.__account_dump_all()


		for i in range(0, 10):
			for x in range(0, 5):
				(http_server, http_client, http_req, http_req_params, http_environ, 
					mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
					"someuser" + str(i), "otherPassWord")

	
				auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		
				self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "authenticated": true}'))
				self.assertEqual(http_server.getinfo()[0], '200 OK')


		db_account_state_after = self.__account_dump_all()

		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_authenticate_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_authenticate_ok()


	def test_ba_handler_authenticate_ok_sometimes(self):
		"""
		Create a series of accounts. Then try to authenticate against these
		accounts, sometimes with a valid password, but using valid Hawk-signature. Should succeed
		when using a valid password, otherwise not.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)


		#
		# Do this a few times, just
		# to make sure all the DB-work
		# is good -- especially the Mohawk stuff.
		#

		for i in range(0, 10):
			self.__account_create("someuser" + str(i), "otherPassWord")

		db_account_state_before = self.__account_dump_all()


		for i in range(0, 10):
			for x in range(0, 6):
				if (x % 2 == 0):
					let_it_succeed = True
				else:
					let_it_succeed = False

				try_login_password = "otherPassWord"

				if (let_it_succeed == False):
					try_login_password += str(x)

				(http_server, http_client, http_req, http_req_params, http_environ, 
					mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
					"someuser" + str(i), try_login_password)

	
				auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

				if (let_it_succeed == True):
					self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "authenticated": true}'))
					self.assertEqual(http_server.getinfo()[0], '200 OK')


				elif (let_it_succeed == False):
					self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Access denied"}'))
					self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_authenticate_ok_sometimes_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_authenticate_ok_sometimes()


	def test_ba_handler_authenticate_disabled_error(self):
		"""
		Create account, then disable it, and try to authenticate against it,
		using valid Hawk header; should result in an error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create("someuser1", "otherPassWord")

		db_account_state_before = self.__account_dump_all()


		db_cursor = self.db_conn.cursor()
		db_cursor.execute("UPDATE accounts SET enabled = 0 WHERE username = 'someuser1'")
		self.db_conn.commit()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			"someuser1", "otherPassWord")


		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Access denied"}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		# Restore the account to previous state
		db_cursor = self.db_conn.cursor()
		db_cursor.execute("UPDATE accounts SET enabled = 1 WHERE username = 'someuser1'")
		self.db_conn.commit()


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_authenticate_disabled_error_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_authenticate_disabled_error()


	def test_ba_handler_authenticate_username_not_ok(self):
		"""
		Create account, try to authenticate but using a username that
		does not exist; should result in a 403 Access denied error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create("someuser1", "otherPassWord")

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			"someuser2", "otherPassWord")


		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Access denied"}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_authenticate_username_not_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_authenticate_username_not_ok()


	def test_ba_handler_authenticate_password_not_ok(self):
		"""
		Create account, try to authenticate but using a password that
		is not valid; should result in a 403 Access denied error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create("someuser1", "otherPassWorddd")

                db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			"someuser1", "otherPassWord")


		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Access denied"}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')

                
		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)

	
	def test_ba_handler_authenticate_password_not_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_authenticate_password_not_ok()


	def test_ba_handler_authenticate_username_missing(self):
		"""
		Create account, try to authenticate but missing the username;
		should result in a missing parameter error. 
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create("someuser1", "otherPassWorddd")


		db_account_state_before = self.__account_dump_all()

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', None, "otherPassWord")


		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username and/or password missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')

                
		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)

	
	def test_ba_handler_authenticate_username_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0
		self.test_ba_handler_authenticate_username_missing()


	def test_ba_handler_authenticate_password_missing(self):
		"""
		Create user, try to authenticate but missing the password;
		should result in a missing parameter error. 
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		
		self.__account_create("someuser1", "otherPassWorddd")
                
		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', "someuser1", None)


		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username and/or password missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')

                
		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_authenticate_password_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_authenticate_password_missing()

		
	def test_ba_handler_authenticate_db_comm_error(self):
		"""
		Create account, try to authenticate using valid username and
		password, but DB-comm error occurs when trying to validate.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
	
		self.__account_create("someuser1", "otherPassWorddd")
                
		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', "someuser1", "otherPassWorddd")


		ba_core_db_name_orig = ba_core.BA_DB_NAME
		ba_core.BA_DB_NAME += "-------------------"

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Database communication error"}'))
		self.assertEqual(http_server.getinfo()[0], '500 Error')


                db_account_state_after = self.__account_dump_all()
                self.assertEqual(db_account_state_before, db_account_state_after)


		ba_core.BA_DB_NAME = ba_core_db_name_orig


	def test_ba_handler_authenticate_db_comm_error_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_authenticate_db_comm_error()


	### User create
	
	def test_ba_handler_account_create_no_sig(self):
		"""
		Attempt to create account, but request is with no Hawk-authorization.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_account_state_before = self.__account_dump_all()
		

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST',
			'someuser', 'otherpassword')


		del(http_environ['HTTP_AUTHORIZATION'])

		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')

	
                db_account_state_after = self.__account_dump_all()
                self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_corrupt_sig(self):
		"""
		Attempt to crate account, simulate that the Hawk-signature
		is corrupt; should result in a 403 Error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_account_state_before = self.__account_dump_all()
		

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST',
			'someuser', 'otherpassword')


		# Maximize likelyhood of replacing some character(s)
		# so that the signature will become corrupted.
		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("a", "s").replace("b", "q").replace("c", "d").replace("d", "e").replace("e", "E").\
			replace("g", "e").replace("h", "e").replace("i", "e").replace("j", "e").replace("k", "e")

		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("A", "s").replace("B", "q").replace("C", "d").replace("D", "e").replace("E", "e").\
			replace("G", "s").replace("H", "q").replace("I", "d").replace("J", "e").replace("K", "e")

		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')

                db_account_state_after = self.__account_dump_all()
                self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_corrupt_username(self):
		"""
		Attempt to create an account, using a valid signature, but remove the 
		username from the request; should result in an error.
			"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_account_state_before = self.__account_dump_all()
		

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', 
			'someuser', 'somepassword')


		http_environ['params']['username'] = "yetanotherusername"

		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')
		
                db_account_state_after = self.__account_dump_all()
                self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_corrupt_password(self):
		"""
		Attempt to create an account, using a valid signature, but remove the 
		password from the request; should result in an error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', 
			'someuser', 'onepassword')


		http_environ['params']['password'] = "yetanotherpassword"

		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')

                db_account_state_after = self.__account_dump_all()
                self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_ok(self):
		"""
		Attempt to create an account, using a valid signature,
		valid username, valid password. Do this multiple times.
		"""

		#self.assertTrue(unittest.ba_db_connect_tested)

		db_account_state_before = self.__account_dump_all()


		#
		# Do this a few times, just
		# to make sure all the DB-work
		# is good -- especially the Mohawk stuff.
		#

		for i in range(0, 50):
			(http_server, http_client, http_req, http_req_params, http_environ, 
				mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', 
				"someuser" + str(i), "otherPassWord")
	
			auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)

			self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "username": "someuser' + str(i) + '"}'))
			self.assertEqual(http_server.getinfo()[0], '200 OK')

		#
		# Do data-integrity checks
		#

		db_account_state_after = list(self.__account_dump_all())

		#
		# We remove from the data-comparision check the newly
		# created accounts -- but first we do some checks.
		#
		# By doing this we can be sure that nothing was touched 
		# that should not have been touched, and that everything
		# that was created, looks good.

		toremove = list()

		for db_row_num in range(0, len(db_account_state_after)):
			# Find 'someuserXX' ...
			if (db_account_state_after[db_row_num][2].find('someuser') == 0):

				# Check if account is enabled
				self.assertTrue(db_account_state_after[db_row_num][1] == 1)

				# Check that password-string is there
				self.assertTrue(len(db_account_state_after[db_row_num][3]) > 0)

				# Check that salt is there
				self.assertTrue(len(db_account_state_after[db_row_num][4]) > 0)

				# Check that created_at is set
				self.assertTrue(db_account_state_after[db_row_num][5] > 0)

				# Make sure that updated_at is not set
				self.assertTrue(db_account_state_after[db_row_num][6] == None)

				# All good. Make sure that this entry is removed
				# from the after-data tuple.
				toremove.append(db_account_state_after[db_row_num])

		
		#
		# We should have created 50 accounts 
		# -- this list should have been populated
		# above.
		#

		self.assertEqual(len(toremove), 50)

		for i in range(0, len(toremove)):
			# Remove all entries that were OK
			db_account_state_after.remove(toremove[i])	

		db_account_state_after = tuple(db_account_state_after)
	
		# All entries we created were removed, things
		# should be exactly the same then as in the beginning.
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_create_ok()


	def test_ba_handler_account_create_username_not_ok(self):
		"""
		Attempt to create an account with an invalid username.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', 
			u"someotherusernameæði", "otherPassWord")


		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username is not acceptable"}'))
		self.assertEqual(http_server.getinfo()[0], '406 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_username_not_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_create_username_not_ok()


	def test_ba_handler_account_create_password_not_ok(self):
		"""
		Attempt to create an account with an invalid password.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', 
			"someuser1", u"otherPassWordæði200"  + chr(2) + chr(3))


		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Password is not acceptable"}'))
		self.assertEqual(http_server.getinfo()[0], '406 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_password_not_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_create_password_not_ok()


	def test_ba_handler_account_create_username_missing(self):
		"""
		Attempt to create an account with a valid password,
		but not username. Request is signed. 
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_account_state_before = self.__account_dump_all()
		

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', None, "otherPassWord")



		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username and/or password missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_username_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_create_username_missing()


	def test_ba_handler_account_create_password_missing(self):
		"""
		Attempt to create an account with a valid username,
		but no password. Request is signed.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_account_state_before = self.__account_dump_all()
		

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', "someuser1", None)


		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username and/or password missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')

		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_password_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_create_password_missing()


	def test_ba_handler_account_create_account_exists(self):
		"""
		Attempt to create an account, with a username that already exists.
		Request is signed.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		
		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', "someuser1", "thatpassword1")

		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "username": "someuser1"}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')


		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', "someuser1", "thatpassword2")

		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)


		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Account exists"}'))
		self.assertEqual(http_server.getinfo()[0], '422 Error')

		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_account_exists_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_create_account_exists()


	def test_ba_handler_account_create_db_comm_error(self):
		"""
		Attempt to create an account, but simulate that
		connection to DB could not be established. 
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create("someuser1", "otherPassWorddd")

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/create', 'POST', "someuser1", "otherPassWorddd")


		ba_core_db_name_orig = ba_core.BA_DB_NAME
		ba_core.BA_DB_NAME += "-------------------"

		auth_handler_ret = ba_core.ba_handler_account_create(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Database communication error"}'))
		self.assertEqual(http_server.getinfo()[0], '500 Error')

		ba_core.BA_DB_NAME = ba_core_db_name_orig


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_create_db_comm_error_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_create_db_comm_error()


	### Account exists

	def test_ba_handler_account_exists_no_sig(self):
		"""
		Check if account exists, but no Hawk authorization header
		is part of request.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('someuser', 'somepassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/exists', 'GET', 
			'someuser')


		del(http_environ['HTTP_AUTHORIZATION'])

		auth_handler_ret = ba_core.ba_handler_account_exists(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_exists_sig_corrupt(self):
		"""
		Check if account exists, but corrupt Hawk authorization header.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)		

		self.__account_create('otheruser', 'somepass')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/exists', 'GET',
			'someuser')


		# Maximize likelyhood of replacing some character(s)
		# so that the signature will become corrupted.
		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("a", "s").replace("b", "q").replace("c", "d").replace("d", "e").replace("e", "E").\
			replace("g", "e").replace("h", "e").replace("i", "e").replace("j", "e").replace("k", "e")

		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("A", "s").replace("B", "q").replace("C", "d").replace("D", "e").replace("E", "e").\
			replace("G", "s").replace("H", "q").replace("I", "d").replace("J", "e").replace("K", "e")

		auth_handler_ret = ba_core.ba_handler_account_exists(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_exists_corrupt_username(self):
		"""
		Check if account exists, but Hawk data is corrupt,
		so request should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'somepassword15')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/exists', 'GET', 
			'someuser')


		http_environ['params']['username'] = "yetanotherusername"

		auth_handler_ret = ba_core.ba_handler_account_exists(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_exists_username_not_ok(self):
		"""
		Check if account exists, but use invalid username.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someusername', 'atleastpassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/exists', 'GET', 
			"someusername---")



		auth_handler_ret = ba_core.ba_handler_account_exists(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username is not acceptable"}'))
		self.assertEqual(http_server.getinfo()[0], '406 Error')

		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_exists_username_not_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_exists_username_not_ok()


	def test_ba_handler_account_exists_username_missing(self):
		"""
		Check if account exists, with no username (but password).
		Should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('someuser', 'ispassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/exists', 'GET', None)


		auth_handler_ret = ba_core.ba_handler_account_exists(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_exists_username_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_exists_username_missing()


	def test_ba_handler_account_exists_db_comm_error(self):
		"""
		Check if account exists, but simulate DB-communication
		error when checking. Should fail gracefully.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create("someuser1", "otherPassWorddd")

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/exists', 'GET', "someuser1", None)


		ba_core_db_name_orig = ba_core.BA_DB_NAME
		ba_core.BA_DB_NAME += "-------------------"

		auth_handler_ret = ba_core.ba_handler_account_exists(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Database communication error"}'))
		self.assertEqual(http_server.getinfo()[0], '500 Error')

		ba_core.BA_DB_NAME = ba_core_db_name_orig

		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_exists_db_comm_error_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_exists_db_comm_error()


	def test_ba_handler_account_exists_ok(self):
		"""
		Check if account exists, with a valid username,
		should succeed.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create("someuser1", "otherPassWorddd")

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/exists', 'GET', "someuser1", None)


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_account_exists(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "message": "Account exists"}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')

		ba_core.BA_DB_NAME = ba_core_db_name_orig


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_exists_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_exists_ok()


	def test_ba_handler_account_exists_no_account_existing(self):
		"""
		Check if account exists when it does not.
		Should return an error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create("someuser1", "otherPassWorddd")

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/exists', 'GET', "someuser2", None)


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_account_exists(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Account does not exist"}'))
		self.assertEqual(http_server.getinfo()[0], '404 Not Found')

		ba_core.BA_DB_NAME = ba_core_db_name_orig


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_exists_no_account_existing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_exists_no_account_existing()


	### Password change 

	def test_ba_handler_account_passwordchange_no_sig(self):
		"""
		Check if account exists, but no Hawk authorization header
		is part of request.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'somepassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			'someuser', 'somepassword')


		del(http_environ['HTTP_AUTHORIZATION'])

		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_sig_corrupt(self):
		"""
		Check if account exists, but corrupt Hawk authorization header.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('otheruser', 'somepass')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT',
			'otheruser', 'someotherpass')


		# Maximize likelyhood of replacing some character(s)
		# so that the signature will become corrupted.
		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("a", "s").replace("b", "q").replace("c", "d").replace("d", "e").replace("e", "E").\
			replace("g", "e").replace("h", "e").replace("i", "e").replace("j", "e").replace("k", "e")

		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("A", "s").replace("B", "q").replace("C", "d").replace("D", "e").replace("E", "e").\
			replace("G", "s").replace("H", "q").replace("I", "d").replace("J", "e").replace("K", "e")

		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_corrupt_username(self):
		"""
		Check if account exists, but Hawk data is corrupt,
		so request should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'somepassword15')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			'someuser', 'somepassword15')


		http_environ['params']['username'] = "yetanotherusername"

		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_corrupt_password(self):
		"""
		Check if account exists, but Hawk data is corrupt,
		so request should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'somepassword15')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			'someuser', 'somepassword15abc')


		http_environ['params']['password'] = "yetanotherpassword"

		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_username_not_ok(self):
		"""
		Check if account exists, but use invalid username.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someusername', 'atleastpassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			"someusername---", 'atleastpasswordB')


		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username is not acceptable"}'))
		self.assertEqual(http_server.getinfo()[0], '406 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_username_not_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_passwordchange_username_not_ok()


	def test_ba_handler_account_passwordchange_password_not_ok(self):
		"""
		Check if account exists, but use invalid password.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someusername', 'atleastpassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			'someusername', 'atleastpassword' + chr(5))


		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Password is not acceptable"}'))
		self.assertEqual(http_server.getinfo()[0], '406 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_password_not_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_passwordchange_password_not_ok()


	def test_ba_handler_account_passwordchange_username_missing(self):
		"""
		Check if account exists, with no username (but password).
		Should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'ispassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			None, 'ispassword')



		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username and/or password missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_username_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_passwordchange_username_missing()


	def test_ba_handler_account_passwordchange_password_missing(self):
		"""
		Check if account exists, with no password (but username).
		Should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'ispassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			'someuser', None)


		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username and/or password missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_password_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_passwordchange_password_missing()


	def test_ba_handler_account_passwordchange_username_and_password_missing(self):
		"""
		Check if account exists, with no password nor username.
		Should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'ispassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			None, None)


		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username and/or password missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')
		

		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_username_and_password_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_passwordchange_username_and_password_missing()


	def test_ba_handler_account_passwordchange_db_comm_error(self):
		"""
		Check if account exists, but simulate DB-communication
		error when checking. Should fail gracefully.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('someuser1', 'otherPassWorddd')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			'someuser1', 'otherPassWorddd')


		ba_core_db_name_orig = ba_core.BA_DB_NAME
		ba_core.BA_DB_NAME += "-------------------"

		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Database communication error"}'))
		self.assertEqual(http_server.getinfo()[0], '500 Error')

		ba_core.BA_DB_NAME = ba_core_db_name_orig


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_db_comm_error_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_passwordchange_db_comm_error()


	def test_ba_handler_account_passwordchange_ok(self):
		"""
		Check if account exists, with a valid username,
		should succeed.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('someuser1', 'otherPassWorddd')

		db_account_state_before = self.__account_dump_all()


		#
		# Try to login with a valid password
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'someuser1', 'otherPassWorddd')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "authenticated": 1}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')


		#
		# Try with an invalid one (but later valid)
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'someuser1', 'other15000PPaSS')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Access denied"}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		#
		# Change password
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			'someuser1', 'other15000PPaSS')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "message": "Updated password"}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')


		#
		# Try to login with (now) a valid password
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'someuser1', 'other15000PPaSS')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "authenticated": 1}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')


		#
		# Try with an invalid one (but previously valid)
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'someuser1', 'otherPassWorddd')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Access denied"}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		ba_core.BA_DB_NAME = ba_core_db_name_orig


		#
		# Some magic needed: 
		#
		# Convert from tuple and back; 
		# see test_ba_handler_account_enable_ok()
		# 

		db_account_state_after = list(self.__account_dump_all())

		db_did_find_change = False

		for db_row_num in range(0, len(db_account_state_after)):
			# Try to find data for this account...
			if (db_account_state_after[db_row_num][2] == 'someuser1'):
				db_account_state_after[db_row_num] = list(db_account_state_after[db_row_num])


				# Make sure username is the in the same row in before 
				# and after data. Necessary so that we can be sure
				# we copy the right data below.
				
				self.assertEqual(db_account_state_before[db_row_num][2], 
					db_account_state_after[db_row_num][2])

				# Verify that updated_at in after-data is higher than 0 (expected)
				self.assertNotEqual(db_account_state_after[db_row_num][6], None)
				self.assertEqual(db_account_state_after[db_row_num][6] > 0, True)

				# Now change it to None 
				db_account_state_after[db_row_num][6] = None


				# Verify that password & salt are strings longer than 0
				self.assertTrue(len(db_account_state_after[db_row_num][3]) > 0)
				self.assertTrue(len(db_account_state_after[db_row_num][4]) > 0)

				# Then copy the original, and overwrite the after data
				db_account_state_after[db_row_num][3] = db_account_state_before[db_row_num][3]
				db_account_state_after[db_row_num][4] = db_account_state_before[db_row_num][4]


				db_account_state_after[db_row_num] = tuple(db_account_state_after[db_row_num])

				db_did_find_change = True

				break


		db_account_state_after = tuple(db_account_state_after)

		self.assertEqual(db_account_state_before, db_account_state_after)
		self.assertTrue(db_did_find_change)


	def test_ba_handler_account_passwordchange_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_passwordchange_ok()


	def test_ba_handler_account_passwordchange_no_account_existing(self):
		"""
		Check if username exists with an account that does
		not exist. Should return an error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser1', 'otherPassWorddd')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/passwordchange', 'PUT', 
			'someuser2', 'otherPassWorddd')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_account_passwordchange(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Account does not exist"}'))
		self.assertEqual(http_server.getinfo()[0], '404 Not Found')

		ba_core.BA_DB_NAME = ba_core_db_name_orig


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_passwordchange_no_account_existing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_passwordchange_no_account_existing()


	### Enable account 

	def test_ba_handler_account_enable_no_sig(self):
		"""
		Check if account exists, but no Hawk authorization header
		is part of request.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'somepassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/enable', 'PUT', 
			'someuser')

		del(http_environ['HTTP_AUTHORIZATION'])

		auth_handler_ret = ba_core.ba_handler_account_enable(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_enable_sig_corrupt(self):
		"""
		Check if account exists, but corrupt Hawk authorization header.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('otheruser', 'somepass')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/enable', 'PUT', 
			'otheruser')


		# Maximize likelyhood of replacing some character(s)
		# so that the signature will become corrupted.
		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("a", "s").replace("b", "q").replace("c", "d").replace("d", "e").replace("e", "E").\
			replace("g", "e").replace("h", "e").replace("i", "e").replace("j", "e").replace("k", "e")

		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("A", "s").replace("B", "q").replace("C", "d").replace("D", "e").replace("E", "e").\
			replace("G", "s").replace("H", "q").replace("I", "d").replace("J", "e").replace("K", "e")

		auth_handler_ret = ba_core.ba_handler_account_enable(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_enable_corrupt_username(self):
		"""
		Check if account exists, but Hawk data is corrupt,
		so request should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('someuser', 'somepassword15')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/enable', 'PUT', 
			'someuser')

		http_environ['params']['username'] = "yetanotherusername"

		auth_handler_ret = ba_core.ba_handler_account_enable(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_enable_username_not_ok(self):
		"""
		Check if account exists, but use invalid username.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someusername', 'atleastpassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/enable', 'PUT', 
			"someusername---")


		auth_handler_ret = ba_core.ba_handler_account_enable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username is not acceptable"}'))
		self.assertEqual(http_server.getinfo()[0], '406 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_enable_username_not_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_enable_username_not_ok()


	def test_ba_handler_account_enable_username_missing(self):
		"""
		Check if account exists, with no username (but password).
		Should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'ispassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/enable', 'PUT', 
			None)


		auth_handler_ret = ba_core.ba_handler_account_enable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_enable_username_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_enable_username_missing()


	def test_ba_handler_account_enable_db_comm_error(self):
		"""
		Check if account exists, but simulate DB-communication
		error when checking. Should fail gracefully.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser1', 'otherPassWorddd')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/enable', 'PUT', 
			'someuser1')


		ba_core_db_name_orig = ba_core.BA_DB_NAME
		ba_core.BA_DB_NAME += "-------------------"

		auth_handler_ret = ba_core.ba_handler_account_enable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Database communication error"}'))
		self.assertEqual(http_server.getinfo()[0], '500 Error')

		ba_core.BA_DB_NAME = ba_core_db_name_orig


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_enable_db_comm_error_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_enable_db_comm_error()


	def test_ba_handler_account_enable_ok(self):
		"""
		Check if account exists, with a valid username,
		should succeed.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser1', 'otherPassWorddd')

		db_account_state_before = self.__account_dump_all()


		#
		# Try to login with a valid password
		# -- should succeed

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'someuser1', 'otherPassWorddd')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "authenticated": 1}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')


		#
		# Then disable the account
		#

		db_cursor = self.db_conn.cursor()
		db_cursor.execute("UPDATE accounts SET enabled = 0 WHERE username = %s", [ "someuser1" ])
		self.db_conn.commit()


		#
		# Try to login with a valid password
		# -- should fail, as it is disabled
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'someuser1', 'otherPassWorddd')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Access denied"}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		#
		# Enable 
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/enable', 'PUT', 
			'someuser1')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_account_enable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "message": "Account enabled"}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')


		#
		# Try to login again - should work 
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'someuser1', 'otherPassWorddd')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "authenticated": 1}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')


		ba_core.BA_DB_NAME = ba_core_db_name_orig


		#
		# Some magic needed: 
		# The DB-data stuff is a tuple of tuples.
		# Now, we expect one column in one row to be changed,
		# i.e. updated_at column. That is expected. But
		# we cannot let exception take place when we compare
		# before-data with after-data, so we change this
		# one column in one row. In order to do that, we must first
		# convert the after-data to list, then change the
		# single row to list, actually change the column's
		# value, and then convert everything again to tuple
		# so that the data-type matches the before-data.
		#

		db_account_state_after = list(self.__account_dump_all())

		db_did_find_change = False

		for db_row_num in range(0, len(db_account_state_after)):
			# Try to find data for this account...
			if (db_account_state_after[db_row_num][2] == 'someuser1'):
				db_account_state_after[db_row_num] = list(db_account_state_after[db_row_num])

				# Verify that updated_at in after-data is higher than 0 (expected)
				self.assertNotEqual(db_account_state_after[db_row_num][6], None)
				self.assertEqual(db_account_state_after[db_row_num][6] > 0, True)

				# Now change it to None 
				db_account_state_after[db_row_num][6] = None

				db_account_state_after[db_row_num] = tuple(db_account_state_after[db_row_num])

				db_did_find_change = True

		db_account_state_after = tuple(db_account_state_after)

		self.assertEqual(db_account_state_before, db_account_state_after)
		self.assertTrue(db_did_find_change)


	def test_ba_handler_account_enable_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_enable_ok()


	def test_ba_handler_account_enable_no_account_existing(self):
		"""
		Check if username exists with an account that does
		not exist. Should return an error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser1', 'otherPassWorddd')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/enable', 'PUT', 
			'someuser2')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_account_enable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Account does not exist"}'))
		self.assertEqual(http_server.getinfo()[0], '404 Not Found')

		ba_core.BA_DB_NAME = ba_core_db_name_orig


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_enable_no_account_existing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_enable_no_account_existing()


	### Disable account 

	def test_ba_handler_account_disable_no_sig(self):
		"""
		Check if account exists, but no Hawk authorization header
		is part of request.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('someuser', 'somepassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/disable', 'PUT', 
			'someuser')


		del(http_environ['HTTP_AUTHORIZATION'])

		auth_handler_ret = ba_core.ba_handler_account_disable(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_disable_sig_corrupt(self):
		"""
		Check if account exists, but corrupt Hawk authorization header.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('otheruser', 'somepass')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/disable', 'PUT', 
			'otheruser')


		# Maximize likelyhood of replacing some character(s)
		# so that the signature will become corrupted.
		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("a", "s").replace("b", "q").replace("c", "d").replace("d", "e").replace("e", "E").\
			replace("g", "e").replace("h", "e").replace("i", "e").replace("j", "e").replace("k", "e")

		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("A", "s").replace("B", "q").replace("C", "d").replace("D", "e").replace("E", "e").\
			replace("G", "s").replace("H", "q").replace("I", "d").replace("J", "e").replace("K", "e")

		auth_handler_ret = ba_core.ba_handler_account_disable(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_disable_corrupt_username(self):
		"""
		Check if account exists, but Hawk data is corrupt,
		so request should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser', 'somepassword15')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/disable', 'PUT', 
			'someuser')


		http_environ['params']['username'] = "yetanotherusername"

		auth_handler_ret = ba_core.ba_handler_account_disable(http_environ, http_server, None)
		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Signature validation of your request failed."}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')

	
		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_disable_username_not_ok(self):
		"""
		Check if account exists, but use invalid username.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someusername', 'atleastpassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/disable', 'PUT', 
			"someusername---")


		auth_handler_ret = ba_core.ba_handler_account_disable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username is not acceptable"}'))
		self.assertEqual(http_server.getinfo()[0], '406 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_disable_username_not_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_disable_username_not_ok()


	def test_ba_handler_account_disable_username_missing(self):
		"""
		Check if account exists, with no username (but password).
		Should fail.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('someuser', 'ispassword')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/disable', 'PUT', 
			None)


		auth_handler_ret = ba_core.ba_handler_account_disable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Username missing"}'))
		self.assertEqual(http_server.getinfo()[0], '400 Error')


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_disable_username_missing_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_disable_username_missing()


	def test_ba_handler_account_disable_db_comm_error(self):
		"""
		Check if account exists, but simulate DB-communication
		error when checking. Should fail gracefully.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)
		
		self.__account_create('someuser1', 'otherPassWorddd')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/disable', 'PUT', 
			'someuser1')


		ba_core_db_name_orig = ba_core.BA_DB_NAME
		ba_core.BA_DB_NAME += "-------------------"

		auth_handler_ret = ba_core.ba_handler_account_disable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Database communication error"}'))
		self.assertEqual(http_server.getinfo()[0], '500 Error')

		ba_core.BA_DB_NAME = ba_core_db_name_orig


		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


	def test_ba_handler_account_disable_db_comm_error_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_disable_db_comm_error()


	def test_ba_handler_account_disable_ok(self):
		"""
		Check if account exists, with a valid username,
		should succeed.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('someuser1', 'otherPassWorddd')

		db_account_state_before = self.__account_dump_all()


		#
		# Try to login with a valid password
		# -- should succeed

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'someuser1', 'otherPassWorddd')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "authenticated": 1}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')


		#
		# Then disable the account
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/disable', 'PUT', 
			'someuser1')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_account_disable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"status": 1, "message": "Account disabled"}'))
		self.assertEqual(http_server.getinfo()[0], '200 OK')


		#
		# Try to login with a valid password
		# -- should fail, as it is disabled
		#

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/authenticate', 'POST', 
			'someuser1', 'otherPassWorddd')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Access denied"}'))
		self.assertEqual(http_server.getinfo()[0], '403 Error')


		ba_core.BA_DB_NAME = ba_core_db_name_orig

	
		#
		# Some magic needed: 
		#
		# Convert from tuple and back; 
		# see test_ba_handler_account_enable_ok()
		# 

		db_account_state_after = list(self.__account_dump_all())

		db_did_find_change = False

		for db_row_num in range(0, len(db_account_state_after)):
			# Try to find data for this account...
			if (db_account_state_after[db_row_num][2] == 'someuser1'):
				db_account_state_after[db_row_num] = list(db_account_state_after[db_row_num])

				# Verify that enabled is 0 (expected)
				self.assertEqual(db_account_state_after[db_row_num][1], 0) 

				# Now change it to 1 so that equality test will succeed
				db_account_state_after[db_row_num][1] = 1


				# Verify that updated_at in after-data is higher than 0 (expected)
				self.assertNotEqual(db_account_state_after[db_row_num][6], None)
				self.assertEqual(db_account_state_after[db_row_num][6] > 0, True)

				# Now change it to None 
				db_account_state_after[db_row_num][6] = None


				db_account_state_after[db_row_num] = tuple(db_account_state_after[db_row_num])

				db_did_find_change = True

				break

		db_account_state_after = tuple(db_account_state_after)

		self.assertEqual(db_account_state_before, db_account_state_after)
		self.assertTrue(db_did_find_change)


	def test_ba_handler_account_disable_ok_mohawk_off(self):
		ba_core.BA_MOHAWK_ENABLED = 0

		self.test_ba_handler_account_disable_ok()


	def test_ba_handler_account_disable_no_account_existing(self):
		"""
		Check if username exists with a account that does
		not exist. Should return an error.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		self.__account_create('someuser1', 'otherPassWorddd')

		db_account_state_before = self.__account_dump_all()


		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req('/v1/account/disable', 'PUT', 
			'someuser2')


		ba_core_db_name_orig = ba_core.BA_DB_NAME

		auth_handler_ret = ba_core.ba_handler_account_disable(http_environ, http_server, None)

		self.assertEqual(json.loads(auth_handler_ret), json.loads('{"error": "Account does not exist"}'))
		self.assertEqual(http_server.getinfo()[0], '404 Not Found')

		ba_core.BA_DB_NAME = ba_core_db_name_orig

	
		db_account_state_after = self.__account_dump_all()
		self.assertEqual(db_account_state_before, db_account_state_after)


		def test_ba_handler_account_disable_no_account_existing_mohawk_off(self):
			ba_core.BA_MOHAWK_ENABLED = 0

			self.test_ba_handler_account_disable_no_account_existing()


if __name__ == '__main__':
	import ba_core

	# Make sure we employ the test database here

	ba_core.BA_DB_NAME_NOT_TESTING = ba_core.BA_DB_NAME
	ba_core.BA_DB_NAME = ba_core.BA_DB_NAME + "_test"

	# Create mock sender_id for Mowhak testing

	ba_core.BA_MOHAWK_ENABLED = 1
	ba_core.BA_MOHAWK_SENDERS = { 
		'testing_entry': {
				'id':		'testing_entry',
				'key':		'ff1a7e041a77f4995cc9337587b004edd1477ddda5fac8ed539890cbc91829af',
				'algorithm':	'sha256',
		}
	}


	ba_core.ORIG_CONFIG_BA_DB_NAME = ba_core.BA_DB_NAME
	ba_core.ORIG_CONFIG_BA_MOHAWK_ENABLED = ba_core.BA_MOHAWK_ENABLED
	ba_core.ORIG_CONFIG_BA_MOHAWK_SENDERS = ba_core.BA_MOHAWK_SENDERS

	unittest.ba_db_connect_tested = False
	
	unittest.main()

