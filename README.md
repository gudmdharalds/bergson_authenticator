# Bergson Authenticator

This is a webservice intended to serve as a standalone backend for authentication. It is mostly useful in those cases where another service handles granting and enforcement of authorization, but does not implement password-storage and management thereof. 

The webservice uses MySQL as database source. Database engine can be changed be supplying a different connector.

It allows for:
- creation of users, with specific passwords
- passwords are hashed with a randomly generated salt
- check if a given username matches existing user 
- disabling and enabling users 
- changing password of user
- optionally uses [Mohawk](https://github.com/kumar303/mohawk/) to validate requested data, assuring that only holders of a secret-key can use the webservice. Note that this is not equal to encryption.

Note: If Mohawk is disabled, but clients still issue Authorization-headers, the webservice will return with an error. This is to catch those accidental cases where verification is silently turned off. 

## API calls

The webservice is RESTful, and allows the following calls to be made:

- /create (POST): Create a new user that will be enabled.


``` 

For instance, one might use cURL to send a request, like this:
$ curl -i  -X POST -H 'Authorization: Hawk ... ' -H 'application/json' -d '{"username":"myusername", "password":"999"}' http://server:port/create 

And the server would respond like this:

HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:20:45 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "username": "myusername"}

Upon failure (Authorization-header skipped from now on):

$ curl -i  -X POST -H 'application/json' -d '{"username":"myusername", "password":"999"}' http://server:port/create ; echo ""
HTTP/1.0 422 Error
Date: Wed, 21 Oct 2015 00:29:46 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Username exists"}

```

- /authenticate (POST): Try to authenticate user

``` 

For example:

$ curl -i  -X POST -H 'application/json' -d '{"username":"myusername", "password":"999"}' http://server:port/authenticate 

HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:28:35 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "authenticated": true}

And upon failure:

$ curl -i  -X POST -H 'application/json' -d '{"username":"myusername", "password":"112"}' http://server:port/authenticate 
HTTP/1.0 403 Error
Date: Wed, 21 Oct 2015 00:30:23 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Access denied"}

```

- /exists (GET) Check if username exists already

```

For example:

$ curl -i  -X GET -H 'application/json' -d '{"username":"myusername"}' http://server:port/exists 
HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:33:24 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "message": "Username exists"}

And upon failure:

$ curl -i  -X GET -H 'application/json' -d '{"username":"myusername2"}' http://server:port/exists 
HTTP/1.0 404 Error
Date: Wed, 21 Oct 2015 00:33:32 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Username does not exist"}

```

- /passwordchange (PUT): Change user's password 

```

For example:

$ curl -i  -X PUT -H 'application/json' -d '{"username":"myusername", "password": "000"}' http://server:port/passwordchange ; echo ""
HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:35:26 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "message": "Updated password"}

And upon failure:

$ curl -i  -X PUT -H 'application/json' -d '{"username":"myusername", "password": "000æ"}' http://server:port/passwordchange ; echo ""
HTTP/1.0 406 Error
Date: Wed, 21 Oct 2015 00:35:51 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Password is not acceptable"}

```

- /disable (PUT): Disable user

```

For example:

$ curl -i  -X PUT -H 'application/json' -d '{"username":"myusername"}' http://server:port/disable ; echo ""
HTTP/1.0 200 OK
Date: Wed, 21 Oct 2015 00:36:16 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"status": 1, "message": "User disabled"}

And upon failure:

$ curl -i  -X PUT -H 'application/json' -d '{"username":"myusername2"}' http://server:port/disable ; echo ""
HTTP/1.0 404 Error
Date: Wed, 21 Oct 2015 00:36:33 GMT
Server: WSGIServer/0.1 Python/2.7.5
Content-type: application/json

{"error": "Username does not exist"}

```

- /enable (PUT): Enable user (identical to /disable in usage)

## Installation

```

$ cd install_folder 

$ unzip authenticator.zip

$ virtualenv python-libs
$ source python-libs/bin/activate
$ pip install -r requirements.txt

$ vim config/... # Edit config file

$ ./server --init
$ ./server

```
