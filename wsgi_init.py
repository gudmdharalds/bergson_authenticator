
from authenticator import *

import os
import pprint

def wsgi_init(http_environ, start_response):
	dispatcher = dispatcher_init()

	return dispatcher.__call__(http_environ, start_response)

