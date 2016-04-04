
#
# Configfile for the authenticator.
#
# Make a copy of this file, name it config.py,
# and change settings in the new file to the appropriate values.
#


#
# Database connection options
#

BA_DB_SERVER = 'localhost'
BA_DB_NAME = 'authenticator'
BA_DB_NAME_TEST = 'authenticator_test_db'
BA_DB_USERNAME = 'authenticator'
BA_DB_PASSWORD = 'replace-me'


#
# This is only used for the standalone server
# -- at what interface to listen and port.
# It is not recommended to run the standalone server
# in production environments, nor to expose it to
# public networks (i.e. internet).

BA_STANDALONE_SERVER_PORT = 8080
BA_STANDALONE_SERVER_ADDR = '127.0.0.1'


#
# Enable or disable Mohawk?
# Also, when should nonce-token expire (in seconds).
#

BA_MOHAWK_ENABLED = 1
BA_MOHAWK_NONCE_EXPIRY = 60


#
# Specify known senders for Mohawk, and their keys.
# These keys should be generated specifically for
# this purpose and should not be re-used elsewhere.
#
# Generate one by executing: head -n 100000 /dev/urandom | sha256sum -
#

BA_MOHAWK_SENDERS = {
        'someone': {     
                'id':'someone' 		# This ID should be the same as the key to this dict,
                'key': 'REPLACE-ME',
                'algorithm': 'sha256'
        },

}


#
# Specify which Hawk-IDs have access to
# what endpoints. You can use ::0 as a
# wildcard.
#
# In this example, 'someone' has access 
# to '/v1/account/authenticate', and
# 'otherone' has access to anything that
# begins with '/v1/acccount/'
#

BA_MOHAWK_PEER_PERMISSIONS = {
	'someone': {
		'endpoints': [
			'/v1/account/authenticate'
		]
	},

	'otherone': {
		'endpoints': [
			'/v1/account/::0'
		]
	}
}


