#!/usr/bin/env python

from ba_core import * 

if __name__ == '__main__':
	#
	# Here begins main().
	#

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

	print('Starting standalone server...')

	# FIXME: Missing signal handling
	# FIXME: KeyboardInterrupt handling

	dispatcher = ba_dispatcher_init()

	httpd = wsgi_simple_server.make_server(BA_STANDALONE_SERVER_ADDR, BA_STANDALONE_SERVER_PORT, dispatcher)

	print('Now serving on port ' + BA_STANDALONE_SERVER_ADDR + ':' + str(BA_STANDALONE_SERVER_PORT))
	print('Waiting for requests ... ')

	httpd.serve_forever()
