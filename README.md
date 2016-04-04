# Bergson Authenticator

This is a microservice intended to serve as a standalone backend for authentication only. This entails that the microservice is only able to create accounts with specific usernames and passwords, but does not store any meta-data about the account (e.g. name of account holder). It does allow for resetting of passwords, and enabling and disabling of accounts. 

The microservice is mostly useful in those cases where another service handles granting and enforcement of authorization, but does not store passwords for accounts and management thereof. 

The microservice uses MySQL as database source. Database engine can be changed be supplying a different connector, although some SQL queries might need a rewrite.

It allows for:
- creation of users, with specific passwords
- passwords hashed with a randomly generated salt
- check if a given username matches existing account 
- disabling and enabling accounts
- changing password of accounts
- optionally uses [Mohawk](https://github.com/kumar303/mohawk/) to validate requested data, assuring that only holders of a secret-key can use the webservice. Note that this does not equal encryption.
- uses Mohawk to control access to resources. The access is based on URLs.

Note: If Mohawk is disabled, but clients still issue Authorization-headers, the webservice will return with an error. This is to catch those accidental cases where verification is silently turned off. 

## API calls

The microservice is implements a RESTful HTTP protocol, supports HTTP OPTIONS for all paths, and allows the following calls to be made:

- /v1/account/create (POST): Create a new user that will be enabled.


``` 

For instance, one might use cURL to send a request, like this:
$ curl -i  -X POST -H 'Authorization: Hawk ... ' -H 'application/json' -d '{"username":"myusername", "password":"999"}' http://server:port/v1/account/create 

And the server would respond like this:

HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:20:45 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "username": "myusername"}

Upon failure (Authorization-header skipped from now on):

$ curl -i  -X POST -H 'application/json' -d '{"username":"myusername", "password":"999"}' http://server:port/v1/account/create ; echo ""
HTTP/1.0 422 Error
Date: Wed, 21 Oct 2015 00:29:46 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Username exists"}

```

- /v1/account/authenticate (POST): Try to authenticate 

``` 

For example:

$ curl -i  -X POST -H 'application/json' -d '{"username":"myusername", "password":"999"}' http://server:port/v1/account/authenticate 

HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:28:35 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "authenticated": true}

And upon failure:

$ curl -i  -X POST -H 'application/json' -d '{"username":"myusername", "password":"112"}' http://server:port/v1/account/authenticate 
HTTP/1.0 403 Error
Date: Wed, 21 Oct 2015 00:30:23 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Access denied"}

```

- /v1/account/exists (GET) Check if account exists already with specified username

```

For example:

$ curl -i  -X GET -H 'application/json' -d '{"username":"myusername"}' http://server:port/v1/account/exists 
HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:33:24 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "message": "Username exists"}

And upon failure:

$ curl -i  -X GET -H 'application/json' -d '{"username":"myusername2"}' http://server:port/v1/account/exists 
HTTP/1.0 404 Error
Date: Wed, 21 Oct 2015 00:33:32 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Username does not exist"}

```

- /v1/account/passwordchange (PUT): Change account password 

```

For example:

$ curl -i  -X PUT -H 'application/json' -d '{"username":"myusername", "password": "000"}' http://server:port/v1/account/passwordchange ; echo ""
HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:35:26 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "message": "Updated password"}

And upon failure:

$ curl -i  -X PUT -H 'application/json' -d '{"username":"myusername", "password": "000æ"}' http://server:port/v1/account/passwordchange ; echo ""
HTTP/1.0 406 Error
Date: Wed, 21 Oct 2015 00:35:51 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Password is not acceptable"}

```

- /v1/account/disable (PUT): Disable account 

```

For example:

$ curl -i  -X PUT -H 'application/json' -d '{"username":"myusername"}' http://server:port/v1/account/disable ; echo ""
HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:36:16 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "message": "User disabled"}

And upon failure:

$ curl -i  -X PUT -H 'application/json' -d '{"username":"myusername2"}' http://server:port/v1/account/disable ; echo ""
HTTP/1.0 404 Error
Date: Wed, 21 Oct 2015 00:36:33 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Username does not exist"}

```

- /v1/account/enable (PUT): Enable account (identical to /disable in usage)

## Installation

### Standalone server

The most simple setup is the standalone server. 

For instance:

```

$ cd install_folder 

$ unzip bergson_authenticator.zip

$ virtualenv python-libs
$ source python-libs/bin/activate
$ pip install -r requirements.txt

$ cp config_example.py config.php
$ vim config.py # Edit config file

$ ./standalone_server --init
$ ./standalone_server

```

### WSGI (for production)

WSGI is prefered in production environments by most users for python-applications.

To setup in a Apache-WSGI environment, see [this post](http://thecodeship.com/deployment/deploy-django-apache-virtualenv-and-mod_wsgi/) for instance. Modification has to be done, though, and that centers on the index.wsgi file used. Below is an example file that can be used:

```python
import os
import sys
import site

# Add the site-packages of the chosen virtualenv to work with
site.addsitedir('my-path-to-installation/python-libs/lib/python2.7/')

# Add the app's directory to the PYTHONPATH
sys.path.append('my-path-to-installation/code') # Here the code to the authenticator should live

# Activate your virtual env
activate_env="my-path-to-installation/python-libs/bin/activate_this.py"
execfile(activate_env, dict(__file__=activate_env))

import wsgi_init

application = wsgi_init.ba_wsgi_init
```

Also, Apache must be configured to pass on the HTTP Authorization header. An example Apache configuration file might look like this:

```
<VirtualHost myhost:80>
        DocumentRoot "my-path-to-installation/code/"
        ServerName myhost

        WSGIScriptAlias / my-path-to-installation/code/index.wsgi
        WSGIPassAuthorization On

        <Directory "my-path-to-installation/code/">
                Options Indexes FollowSymLinks
                AllowOverride all
                Require all granted
        </Directory>
</VirtualHost>
```

Note that the "my-path-to-installation/code" needs to be replaced with full-path to the folder where the authenticator code lives.

Otherwise, the instructions referred to above should work.

To install the database-tables, it is recommended to run the application in standalone-mode with the --init argument (see above).

# Tests

This project comes with a through unit-testing suite. This includes  testing the API calls, all functions outside the API, and data-integrity checks of all operations.

To run the test-suite, first set up Bergson as advised above, then run:

```
python tests.py -v 

```

Note that Mohawk has to be installed for this to work, and you must have the database-connection correctly set up. In addition, the user must have full access (i.e. DROP, CREATE, SELECT, INSERT, UPDATE) to a test-database. The name of this database is configurable in the config-file.

Also note that the test might print out the following text while texting:

```
No handlers could be found for logger "mohawk.base"
```

this can be safely ignored.




