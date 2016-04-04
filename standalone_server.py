#!/usr/bin/env python
# -*- coding: utf-8 -*-

if __name__ == '__main__':
	#
	# Here begins main().
	#

        
	#
	# Scrub environment -- get rid of everything.
	#
       
	import os
 
	os_environ_keys = os.environ.keys()

	for os_environ_keys_item in os_environ_keys:
		os.environ.pop(os_environ_keys_item, None)

	#
	# Now import the core BA functions 
	# 
	
	from ba_core import * 

	#
	# Register handlers which deal with requests.
	# They will then take care of things.
	#

	argv_parser = argparse.ArgumentParser(description='Simple user-management webservice')
	argv_parser.add_argument('-i', '--init', required=False, dest='init', 
		action='store_true', help='initialize database tables')

	argv = argv_parser.parse_args()

	if (argv.init == True):
		ba_db_create_tables()
		print('Ready for use. Now launch without --init')
		sys.exit(0)

	print('Starting standalone server... - press CTRL + C to exit')

	dispatcher = ba_dispatcher_init()

	httpd = wsgi_simple_server.make_server(ba_config.BA_STANDALONE_SERVER_ADDR, ba_config.BA_STANDALONE_SERVER_PORT, dispatcher)

	print('Now serving on port ' + ba_config.BA_STANDALONE_SERVER_ADDR + ':' + str(ba_config.BA_STANDALONE_SERVER_PORT))
	print('Waiting for requests ... ')

	httpd.serve_forever()
