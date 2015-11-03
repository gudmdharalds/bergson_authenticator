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
		f_http_input_file.write(req_data_json)
		f_http_input_file.close()


		f_http_input_file = open(http_input_file_info[1], 'r')

		f_dev_null = open('/dev/null', 'w')
                 
		req_headers = {
			'CONTENT_LENGTH': len(req_data_json),
			'CONTENT_TYPE': 'application/json',
			'GATEWAY_INTERFACE': 'CGI/1.1',
			'HTTP_ACCEPT': '*/*',
			'HTTP_HOST': req_host,
			'HTTP_USER_AGENT': 'curl/7.29.0',
			'PATH_INFO': req_path,
			'QUERY_STRING': '',
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

		path_dispatcher.register('PUT', '/v1/path1', dummy_call_func1, [ 'somestring1' ])
		path_dispatcher.register('GET', '/v1/path1', dummy_call_func2, [ 'somestring2' ])
		path_dispatcher.register('GET', '/v1/path2', dummy_call_func2, [ 'somestring3' ])

		self.assertEqual(path_dispatcher.pathmap, 
			{
				('put', '/v1/path1'): { 'handler': dummy_call_func1, 
						'args_extra' : [ 'somestring1' ] },
				('get', '/v1/path1'): { 'handler': dummy_call_func2, 
						'args_extra' : [ 'somestring2' ] },
				('get', '/v1/path2'): { 'handler': dummy_call_func2, 
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
			'PATH_INFO': '/v1/create',
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
		path_dispatcher.register('POST', '/v1/create', self.__test_call_json_handler_main, None)
		path_dispatcher.register('POST', '/v1/create_not_called', self.__test_call_json_handler_second, None)
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
			'PATH_INFO': '/v1/create',
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
		path_dispatcher.register('GET', '/v1/create', self.__test_call_text_plain_handler_main, None)
		path_dispatcher.register('GET', '/v1/create_not_called', self.__test_call_text_plain_handler_second, None)
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
			'PATH_INFO': '/v1/create',
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
		path_dispatcher.register('POST', '/v1/create', self.__test_call_form_urlencoded_handler_main, None)
		path_dispatcher.register('POST', '/v1/create_not_called', self.__test_call_form_urlencoded_handler_second, None)
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
			'PATH_INFO': '/v1/create',
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
		path_dispatcher.register('GET', '/v1/create', self.__test_call_404_handler_main, None)
		path_dispatcher.register('GET', '/v1/create_not_called', self.__test_call_404_handler_second, None)
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
	# FIXME: No mohawk tests

	def test_ba_http_resp_404(self):
		http_server_emulator_instance = http_server_emulator()
		http_resp_body = ba_core.ba_http_resp_404(None, http_server_emulator_instance, None)

		self.assertEqual(http_resp_body, '{"error": "Not found"}')
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

		self.assertEqual(http_resp_body, '{"somefield2": "somedata2", "somefield1": "somedata1"}')

	def test_ba_http_resp_json200b(self):
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

		self.assertEqual(http_resp_body, '{"somefield2": "somedata2", "somefield1": "somedata1"}')


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

		self.assertEqual(http_resp_body, '{"somefield2": "somedata2", "somefield1": "somedata1"}')

	def test_ba_http_resp_json404b(self):
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

		self.assertEqual(http_resp_body, '{"somefield2": "somedata2", "somefield1": "somedata1"}')


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
	
		self.assertEqual(http_resp_body, '{"somefield2": "somedata2", "somefield1": "somedata1"}')

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

		self.assertEqual(http_resp_body, '{"somefield2": "somedata2", "somefield1": "somedata1"}')

class TestDBRoutines(unittest.TestCase):
	# FIXME: Implement 
	def test_db_connect(self):
		unittest.ba_db_connect_tested = True

		# Make sure we will be connecting to a test-database
		self.assertEqual(ba_core.BA_DB_NAME.rfind('_test'), len(ba_core.BA_DB_NAME) - len('_test'))
		self.assertEqual(ba_core.BA_DB_NAME.split('_test'), [ ba_core.BA_DB_NAME_ORIGINAL, '' ])

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
		db_cursor.execute("DESC users")

		db_table_info_users = db_cursor.fetchall()

		self.assertEqual(db_table_info_users[0], ('id', 'bigint(20)', 'NO', 'PRI', None, 'auto_increment'))
		self.assertEqual(db_table_info_users[1], ('enabled', 'int(11)', 'NO', '', '0', ''))
		self.assertEqual(db_table_info_users[2], ('username', 'varchar(128)', 'NO', 'UNI', None, ''))
		self.assertEqual(db_table_info_users[3], ('password_hashed', 'varchar(256)', 'NO', '', None, ''))
		self.assertEqual(db_table_info_users[4], ('salt', 'varchar(128)', 'NO', '', None, ''))
		self.assertEqual(db_table_info_users[5], ('created_at', 'bigint(20)', 'NO', '', None, ''))
		self.assertEqual(db_table_info_users[6], ('updated_at', 'bigint(20)', 'YES', '', None, ''))


		db_cursor = db_conn.cursor()
		db_cursor.execute("DESC nonce")

		db_table_info_nonce = db_cursor.fetchall()

		self.assertEqual(db_table_info_nonce[0], ('id', 'bigint(20)', 'NO', 'PRI', None, 'auto_increment'))
		self.assertEqual(db_table_info_nonce[1], ('nonce_key_hash', 'varchar(64)', 'NO', 'MUL', None, ''))
		self.assertEqual(db_table_info_nonce[2], ('timestamp', 'bigint(20)', 'NO', '', None, ''))

		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE users")

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

		db_conn = ba_core.ba_db_connect()

		ba_core.ba_db_create_tables()

		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/create'
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
			ba_core.ba_signature(db_conn, http_environ, req_data_mohawk_test)

                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE users")
                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")

		db_conn.close()


	def test_ba_signature_mohawk_on_invalid_http_path(self):
		"""
		Try if validation fails with Mohawk turned on.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_conn = ba_core.ba_db_connect()

		ba_core.ba_db_create_tables()

		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/create'
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
				ba_core.ba_signature(db_conn, http_environ, req_data_mohawk_test)

                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE users")
                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")

		db_conn.close()


	def test_ba_signature_mohawk_on_injected_data(self):
		"""
		Try if validation fails with Mohawk turned on.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_conn = ba_core.ba_db_connect()

		ba_core.ba_db_create_tables()

		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/create'
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
				ba_core.ba_signature(db_conn, http_environ, req_data_mohawk_test)

                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE users")
                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")

		db_conn.close()


	def test_ba_signature_mohawk_on_repeated_token(self):
		"""
		Try if validation fails with Mohawk turned on.
		"""

		self.assertTrue(unittest.ba_db_connect_tested)

		db_conn = ba_core.ba_db_connect()

		ba_core.ba_db_create_tables()

		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/create'
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
			ba_core.ba_signature(db_conn, http_environ, req_data_mohawk_test)

			# Try repeatedly to re-use token -- should not work
			for x in range(0, 10):
				with self.assertRaises(mohawk.exc.AlreadyProcessed):
					ba_core.ba_signature(db_conn, http_environ, req_data_mohawk_test)


                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE users")
                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")

		db_conn.close()


	def test_ba_signature_mohawk_off_all_ok(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		db_conn = ba_core.ba_db_connect()

		ba_core.ba_db_create_tables()

		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/create'
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
			ba_core.ba_signature(db_conn, http_environ, req_data_mohawk_test)

			ba_core.BA_MOHAWK_ENABLED = 1

                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE users")
                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")

		db_conn.close()


	def test_ba_signature_mohawk_off_auth_headers_sent(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		db_conn = ba_core.ba_db_connect()

		ba_core.ba_db_create_tables()

		#
		# Because ba_core.ba_signature() contains a probability
		# condition, repeat this quite often
		#

		for i in range(0, 250):
			http_client = http_client_emulator()	

			req_method = 'POST'
			req_host = '127.0.0.1:8080'
			req_path = '/v1/create'
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
				ba_core.ba_signature(db_conn, http_environ, req_data_mohawk_test)

			ba_core.BA_MOHAWK_ENABLED = 1
 
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE users")
                
		db_cursor = db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")

		db_conn.close()


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
	def __init_db(self):
		self.db_conn = ba_core.ba_db_connect()
		ba_core.ba_db_create_tables()


	def __cleanup(self):
		db_cursor = self.db_conn.cursor()
		db_cursor.execute("DROP TABLE users")

		db_cursor = self.db_conn.cursor()
		db_cursor.execute("DROP TABLE nonce")

		self.db_conn.close

	def __user_create(self, username, password):
		http_server = http_server_emulator()
		http_client = http_client_emulator()

		http_req = {
			'method': 'POST',
			'host': 'localhost',
			'path': '/v1/create'
		}

		http_req_params = { 
			'username' : username, 
			'password' : password 
		}

		ba_core.BA_MOHAWK_ENABLED = 0

		(http_parsed_environ, http_parsed_params) = http_client.request_generate(
			http_req['method'], http_req['host'], http_req['path'], None, http_req_params)

		ba_core.ba_handler_user_create(http_parsed_environ, http_server, None)

		ba_core.BA_MOHAWK_ENABLED = 1


	def __gen_basic_http_req(self, username = None, password = None, mohawk_sender_id = None):
		if (username == None):
			username = 'myuser'

		if (password == None):
			password = 'mypass'

		if (mohawk_sender_id == None):
			mohawk_sender_id = 'testing_entry'		

			http_server = http_server_emulator()
		http_client = http_client_emulator()

		http_req = {
			'method': 'POST',
			'host': 'localhost',
			'path': '/v1/authenticate'
		}

		http_req_params = { 
		}

		if (username != None):
			http_req_params['username'] = username

		if (password != None):
			http_req_params['password'] = password


		(http_parsed_environ, http_parsed_params) = http_client.request_generate(http_req['method'], http_req['host'], http_req['path'], 
			None, http_req_params)


		# Sign the request
		mohawk_sender_sig = mohawk.Sender(ba_core.ba_signature_lookup_sender(mohawk_sender_id),
			"http://" + http_req['host'] + http_req['path'] + "",
			http_req['method'],
			content="username=" + http_parsed_params["username"] + "&" + "password=" + http_parsed_params["password"],
			content_type=http_parsed_environ['CONTENT_TYPE'])

		http_parsed_environ['HTTP_AUTHORIZATION'] = mohawk_sender_sig.request_header

		return (http_server, http_client, http_req, http_req_params, http_parsed_environ, mohawk_sender_sig)

	
	def test_ba_handler_authenticate_user_no_sig(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()

		(http_server, http_client, http_req, http_req_params, http_environ, mohawk_sender_sig) = self.__gen_basic_http_req()
		ba_core.BA_MOHAWK_ENABLED = 1

		del(http_environ['HTTP_AUTHORIZATION'])

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		self.assertEqual(auth_handler_ret, '{"error": "Signature validation of your request failed."}')
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		self.__cleanup()



	def test_ba_handler_authenticate_user_currupt_sig(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()

		(http_server, http_client, http_req, http_req_params, http_environ, mohawk_sender_sig) = self.__gen_basic_http_req()
		ba_core.BA_MOHAWK_ENABLED = 1

		# Maximize likelyhood of replacing some character(s)
		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("a", "s").replace("b", "q").replace("c", "d").replace("d", "e").replace("e", "E").\
			replace("g", "e").replace("h", "e").replace("i", "e").replace("j", "e").replace("k", "e")

		http_environ['HTTP_AUTHORIZATION'] = http_environ['HTTP_AUTHORIZATION'].\
			replace("A", "s").replace("B", "q").replace("C", "d").replace("D", "e").replace("E", "e").\
			replace("G", "s").replace("H", "q").replace("I", "d").replace("J", "e").replace("K", "e")

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		self.assertEqual(auth_handler_ret, '{"error": "Signature validation of your request failed."}')
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		self.__cleanup()

	def test_ba_handler_authenticate_user_currupt_username(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()

		(http_server, http_client, http_req, http_req_params, http_environ, mohawk_sender_sig) = self.__gen_basic_http_req()
		ba_core.BA_MOHAWK_ENABLED = 1

		http_environ['params']['username'] = "yetanotherusername"

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		self.assertEqual(auth_handler_ret, '{"error": "Signature validation of your request failed."}')
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		self.__cleanup()

	def test_ba_handler_authenticate_user_currupt_password(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()

		(http_server, http_client, http_req, http_req_params, http_environ, mohawk_sender_sig) = self.__gen_basic_http_req()
		ba_core.BA_MOHAWK_ENABLED = 1

		http_environ['params']['password'] = "yetanotherpassword"

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		self.assertEqual(auth_handler_ret, '{"error": "Signature validation of your request failed."}')
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		self.__cleanup()


	def test_ba_handler_authenticate_user_sig_ok(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()

		(http_server, http_client, http_req, http_req_params, http_environ, mohawk_sender_sig) = self.__gen_basic_http_req()
		ba_core.BA_MOHAWK_ENABLED = 1

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		# Normal error: The user does not exist
		self.assertEqual(auth_handler_ret, '{"error": "Access denied"}')
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		self.__cleanup()


	def test_ba_handler_authenticate_user_ok(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()

		#
		# Do this a few times, just
		# to make sure all the DB-work
		# is good -- especially the Mohawk stuff.
		#

		for i in range(0, 10):
			self.__user_create("someuser" + str(i), "otherPassWord")

			for x in range(0, 5):
				(http_server, http_client, http_req, http_req_params, http_environ, 
					mohawk_sender_sig) = self.__gen_basic_http_req("someuser" + str(i), "otherPassWord")

				ba_core.BA_MOHAWK_ENABLED = 1
	
				auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)
		
				self.assertEqual(auth_handler_ret, '{"status": 1, "authenticated": true}')
				self.assertEqual(http_server.getinfo()[0], '200 OK')

		self.__cleanup()


	def test_ba_handler_authenticate_user_disabled_error(self):
#		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()
		self.__user_create("someuser1", "otherPassWord")

		db_cursor = self.db_conn.cursor()
		db_cursor.execute("UPDATE users SET enabled = 0 WHERE username = 'someuser1'")
		self.db_conn.commit()

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req("someuser1", "otherPassWord")

		ba_core.BA_MOHAWK_ENABLED = 1

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(auth_handler_ret, '{"error": "Access denied"}')
		self.assertEqual(http_server.getinfo()[0], '200 OK')

		self.__cleanup()


	def test_ba_handler_authenticate_user_username_not_ok(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()
		self.__user_create("someuser1", "otherPassWord")

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req("someuser2", "otherPassWord")

		ba_core.BA_MOHAWK_ENABLED = 1

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(auth_handler_ret, '{"error": "Access denied"}')
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		self.__cleanup()


	def test_ba_handler_authenticate_user_password_not_ok(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()
		self.__user_create("someuser1", "otherPassWorddd")

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req("someuser1", "otherPassWord")

		ba_core.BA_MOHAWK_ENABLED = 1

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(auth_handler_ret, '{"error": "Access denied"}')
		self.assertEqual(http_server.getinfo()[0], '403 Error')

		self.__cleanup()
	

	def test_ba_handler_authenticate_user_username_missing(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()
		self.__user_create("someuser1", "otherPassWorddd")

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req(None, "otherPassWord")

		ba_core.BA_MOHAWK_ENABLED = 1

		del(http_environ['params']['username'])

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(auth_handler_ret, '{"error": "Username and/or password missing"}')
		self.assertEqual(http_server.getinfo()[0], '400 Error')

		self.__cleanup()


	def test_ba_handler_authenticate_user_password_missing(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()
		self.__user_create("someuser1", "otherPassWorddd")

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req("someuser1", None)

		ba_core.BA_MOHAWK_ENABLED = 1

		del(http_environ['params']['password'])

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(auth_handler_ret, '{"error": "Username and/or password missing"}')
		self.assertEqual(http_server.getinfo()[0], '400 Error')

		self.__cleanup()


	def test_ba_handler_authenticate_user_db_comm_error(self):
		self.assertTrue(unittest.ba_db_connect_tested)

		self.__init_db()
		self.__user_create("someuser1", "otherPassWorddd")

		(http_server, http_client, http_req, http_req_params, http_environ, 
			mohawk_sender_sig) = self.__gen_basic_http_req("someuser1", "otherPassWorddd")

		ba_core.BA_MOHAWK_ENABLED = 1

		ba_core_db_name_orig = ba_core.BA_DB_NAME
		ba_core.BA_DB_NAME += "-------------------"

		auth_handler_ret = ba_core.ba_handler_authenticate(http_environ, http_server, None)

		self.assertEqual(auth_handler_ret, '{"error": "Database communication error"}')
		self.assertEqual(http_server.getinfo()[0], '500 Error')

		ba_core.BA_DB_NAME = ba_core_db_name_orig

		self.__cleanup()






if __name__ == '__main__':
	import ba_core

	# Make sure we emply the test database here
	ba_core.BA_DB_NAME_ORIGINAL = ba_core.BA_DB_NAME
	ba_core.BA_DB_NAME = ba_core.BA_DB_NAME + "_test"
	ba_core.BA_MOHAWK_SENDERS = { 
		'testing_entry': {
				'id':		'testing_entry',
				'key':		'ff1a7e041a77f4995cc9337587b004edd1477ddda5fac8ed539890cbc91829af',
				'algorithm':	'sha256',
		}
	}

	unittest.ba_db_connect_tested = False
	unittest.main()

