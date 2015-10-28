#!/usr/bin/env python

from authenticator import * 

if __name__ == '__main__':
	#
	# Here begins main().
	#
	# Register handlers which deal with requests.
	# They will then take care of things.
	#

	argv_parser = argparse.ArgumentParser(description='Simple user-management webservice')
	argv_parser.add_argument('-i', '--init', required=False, dest='init', 
		action='store_true', help='initialize database tables')

	argv = argv_parser.parse_args()

	if (argv.init == True):
		db_create_tables()
		print('Ready for use. Now launch without --init')
		sys.exit(0)

	print('Starting standalone server...')

	# FIXME: Missing signal handling
	# FIXME: KeyboardInterrupt handling

	dispatcher = dispatcher_init()

	httpd = wsgi_simple_server.make_server(AUTHENTICATOR_SERVER_ADDR, AUTHENTICATOR_SERVER_PORT, dispatcher)

	print('Now serving on port ' + AUTHENTICATOR_SERVER_ADDR + ':' + str(AUTHENTICATOR_SERVER_PORT))
	print('Waiting for requests ... ')

	httpd.serve_forever()
