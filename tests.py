#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import ba_core
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

		http_input_file_path = tempfile.mkstemp()
		f_http_input_file = open(http_input_file_path[1], 'w')
		f_http_input_file.write('{"username":"myuser","password":"mypass"}')
		f_http_input_file.close()

		f_http_input_file = open(http_input_file_path[1], 'r')
		
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
		os.remove(http_input_file_path[1])

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

		http_input_file_path = tempfile.mkstemp()
		f_http_input_file = open(http_input_file_path[1], 'w')
		f_http_input_file.write('')
		f_http_input_file.close()

		f_http_input_file = open(http_input_file_path[1], 'r')
		
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
		os.remove(http_input_file_path[1])

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

		http_input_file_path = tempfile.mkstemp()
		f_http_input_file = open(http_input_file_path[1], 'w')
		f_http_input_file.write('username=myyetotheruser&password=myyetotherpass')
		f_http_input_file.close()

		f_http_input_file = open(http_input_file_path[1], 'r')
		
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
		os.remove(http_input_file_path[1])

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

		http_input_file_path = tempfile.mkstemp()
		f_http_input_file = open(http_input_file_path[1], 'w')
		f_http_input_file.write('')
		f_http_input_file.close()

		f_http_input_file = open(http_input_file_path[1], 'r')
		
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
		os.remove(http_input_file_path[1])

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
		self.assertEqual(db_table_info_nonce[1], ('nonce_key_hash', 'varchar(64)', 'NO', '', None, ''))
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



if __name__ == '__main__':
	# Make sure we emply the test database here
	ba_core.BA_DB_NAME_ORIGINAL = ba_core.BA_DB_NAME
	ba_core.BA_DB_NAME = ba_core.BA_DB_NAME + "_test"

	unittest.main()

