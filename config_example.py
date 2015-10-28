
#
# Configfile for the authenticator.
#
# Make a copy of this file, name it config.py,
# and change settings in the new file to the appropriate values.
#


#
# Database connection options
#

BA_AUTH_DB_SERVER = 'localhost'
BA_AUTH_DB_NAME = 'authenticator'
BA_AUTH_DB_USERNAME = 'authenticator'
BA_AUTH_DB_PASSWORD = 'replace-me'

#
# This is only used for the standalone server
# -- at what interface to listen and port.
# It is not recommended to run the standalone server
# in production environments, not to expose it to
# public networks (i.e. internet).

BA_AUTH_SERVER_PORT = 8080
BA_AUTH_SERVER_ADDR = '127.0.0.1'

#
# Enable or disable Mohawk?
# Also, when should nonce-token expire (in seconds).
#

BA_AUTH_MOHAWK_ENABLED = 1
BA_AUTH_MOHAWK_NONCE_EXPIRY = 60

#
# Specify known senders for Mohawk, and their keys.
# These keys should be generated specifically for
# this purpose and should not be re-used elsewhere.
#
# Generate one by executing: head -n 100000 /dev/urandom | sha256sum -
#

BA_AUTH_MOHAWK_SENDERS = {
        'someone': {     
                'id':'someone' 		# This ID should be the same as the key to this dict,
                'key': 'REPLACE-ME',
                'algorithm': 'sha256'
        },

}

