![Build Status](https://travis-ci.org/Salesflare/hapi-auth-bearer-simple.svg?branch=master)  ![](https://david-dm.org/salesflare/hapi-auth-bearer-simple.svg) ![](https://david-dm.org/salesflare/hapi-auth-bearer-simple/dev-status.svg) ![](https://david-dm.org/salesflare/hapi-auth-bearer-simple/peer-status.svg)

# Hapi authentication plugin

[**hapi**](https://github.com/hapijs/hapi) Bearer Token Authentication Scheme

If you have any problems and/or questions make a new [**issue**](https://github.com/Salesflare/hapi-auth-bearer-simple/issues).

If you want to contribute feel free to fork and add a pull request or again make an [**issue**](https://github.com/Salesflare/hapi-auth-bearer-simple/issues).

The plugin requires validating a token passed in by the bearer authorization header. The validation function is something you have to provide to the plugin.

Example: 

```javascript
var Hapi = require('hapi');

var server = new Hapi.Server('localhost', 8000);


server.pack.register(require('hapi-auth-bearer-simple'), function (err) {
    if (err) throw err;

    server.auth.strategy('basic', 'bearerAuth', {
        validateFunction: validateFunction
    });

    // Add a standard route here as example
    server.route({
        method: 'GET',
        path: '/',
        handler: function (request, reply) {
            reply({
                success: true
            });
        },
        config: {
            auth: 'basic'
        }
    });

    server.start(function () {
        console.log('Server started at: ' + server.info.uri);
    });
});

var validateFunction = function (token, callback) {
    // Use a real strategy here to check if the token is valid
    if (token === "123456789") {
        callback(null, true, {
            token: token
        });
    } else {
        callback(null, false, {
            token: token
        });
    }
};
```

- `validateFunc` - (required) a token lookup and validation function with the signature `function(token, callback)`
    - `token` - the auth token received from the client.
    - `callback` - a callback function with the signature `function(err, isValid, credentials)` where:
        - `err` - any error.
        - `isValid` - `true` if both the username was found and the password matched, otherwise `false`.
        - `credentials` - an object passed back to the plugin and which will become available in the `request`object as `request.auth.credentials`. Normally credentials are only included when `isValid`is `true`. This object can be only the token as in the example but is preferably all the info you need from the authenticated user
