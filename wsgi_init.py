
from authenticator import *

import os
import pprint

def ba_wsgi_init(http_environ, start_response):
	dispatcher = ba_dispatcher_init()

	return dispatcher.__call__(http_environ, start_response)

