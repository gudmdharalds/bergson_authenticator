#!/usr/bin/env python

import unittest

import ba_core
import pprint
import tempfile
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
	test_call_1_res = {
		'__test_call_1_handler_second_called' : False
	}
	
	test_call_2_res = {
		'__test_call_2_handler_second_called' : False
	}

	test_call_3_res = {
		'__test_call_3_handler_second_called' : False
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


	def test_call_1(self):

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
		path_dispatcher.register('POST', '/v1/create', self.__test_call_1_handler_main, None)
		path_dispatcher.register('POST', '/v1/create_not_called', self.__test_call_1_handler_second, None)
		path_dispatcher.__call__(http_headers, self.__test_call_1_handler_main)

		#
		# Close temporary file and remove it.
		#
	
		f_http_input_file.close()	
		os.remove(http_input_file_path[1])

		self.assertEqual(self.test_call_1_res, 
			{ 
				'http_environ' : http_headers,
				'args_extra' : None,
				'__test_call_1_handler_second_called' : False
			}
		)

		self.assertEqual(self.test_call_1_res['http_environ']['params'], { "username": "myuser", "password": "mypass" })	

		self.assertEqual(self.test_call_1_res['http_environ']['CONTENT_TYPE'], 'application/json')
	
		return False

	def __test_call_1_handler_main(self, http_environ, start_response, args_extra):
		self.test_call_1_res['http_environ'] = http_environ
		self.test_call_1_res['args_extra'] = args_extra

		return True

	def __test_call_1_handler_second(self, http_environ, start_response, args_extra):
		self.test_call_1_res = { 
			'__test_call_1_handler_second_called': True 
		}

		return True


	def test_call_2(self):
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
		path_dispatcher.register('GET', '/v1/create', self.__test_call_2_handler_main, None)
		path_dispatcher.register('GET', '/v1/create_not_called', self.__test_call_2_handler_second, None)
		path_dispatcher.__call__(http_headers, self.__test_call_2_handler_main)

		#
		# Close temporary file and remove it.
		#
	
		f_http_input_file.close()	
		os.remove(http_input_file_path[1])

		self.assertEqual(self.test_call_2_res, 
			{ 
				'http_environ' : http_headers,
				'args_extra' : None,
				'__test_call_2_handler_second_called' : False
			}
		)

		self.assertEqual(self.test_call_2_res['http_environ']['params'], 
			{ 
				"username": "myotheruser", 
				"password": "myotherpass" 
			}
		)

		self.assertEqual(self.test_call_2_res['http_environ']['CONTENT_TYPE'], 'text/plain')
	
		return False

	def __test_call_2_handler_main(self, http_environ, start_response, args_extra):
		self.test_call_2_res['http_environ'] = http_environ
		self.test_call_2_res['args_extra'] = args_extra

		return True

	def __test_call_2_handler_second(self, http_environ, start_response, args_extra):
		self.test_call_2_res = { 
			'__test_call_2_handler_second_called': True 
		}

		return True


	def test_call_3(self):
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
		path_dispatcher.register('GET', '/v1/create', self.__test_call_3_handler_main, None)
		path_dispatcher.register('GET', '/v1/create_not_called', self.__test_call_3_handler_second, None)
		path_dispatcher.__call__(http_headers, http_server_emulator_instance)


		#
		# Close temporary file and remove it.
		#
	
		f_http_input_file.close()	
		os.remove(http_input_file_path[1])

		self.assertEqual(self.test_call_3_res, 
			{ 
				'__test_call_3_handler_second_called' : False
			}
		)

		self.assertEqual(http_server_emulator_instance.getinfo(),       ('404 Not Found',
			[ ('Content-type', 'application/json'),
				('Cache-Control', 'no-cache'),
				('Pragma', 'no-cache')
			]
		))

		return False

	def __test_call_3_handler_main(self, http_environ, start_response, args_extra):
		self.test_call_3_res['http_environ'] = http_environ
		self.test_call_3_res['args_extra'] = args_extra

		return True

	def __test_call_3_handler_second(self, http_environ, start_response, args_extra):
		self.test_call_3_res = { 
			'__test_call_3_handler_second_called': True 
		}

		return True


class TestHttpRespMethods(unittest.TestCase):
	def test_ba_http_resp_404(self):
		http_server_emulator_instance = http_server_emulator()
		http_resp_body = ba_core.ba_http_resp_404(None, http_server_emulator_instance, None)

		self.assertEqual(http_resp_body, '{"error": "Not found"}')
		self.assertEqual(http_server_emulator_instance.getinfo(),	('404 Not Found', 
			[ ('Content-type', 'application/json'), 
				('Cache-Control', 'no-cache'), 
				('Pragma', 'no-cache')
			]
		))


if __name__ == '__main__':
		unittest.main()

