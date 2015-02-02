![Build Status](https://travis-ci.org/Salesflare/hapi-auth-bearer-simple.svg?branch=master)  ![](https://david-dm.org/salesflare/hapi-auth-bearer-simple.svg) ![](https://david-dm.org/salesflare/hapi-auth-bearer-simple/dev-status.svg) ![](https://david-dm.org/salesflare/hapi-auth-bearer-simple/peer-status.svg)
[![Code Climate](https://codeclimate.com/github/Salesflare/hapi-auth-bearer-simple/badges/gpa.svg)](https://codeclimate.com/github/Salesflare/hapi-auth-bearer-simple)

# Hapi authentication plugin

> [**hapi**](https://github.com/hapijs/hapi) Bearer Token Authentication Scheme

## What
The plugin requires validating a token passed in by the bearer authorization header. The validation function is something you have to provide to the plugin.

## How

```javascript
server.register(require('hapi-auth-bearer-simple'), function (err) {
    if (err) throw err;

    server.auth.strategy('bearer', 'bearerAuth', {
        validateFunction: validateFunction
    });

    // Add a standard route here as example
    server.route({
        method: 'GET',
        path: '/',
        handler: function (request, reply) {
            reply({ success: true });
        },
        config: {
            auth: 'bearer'
        }
    });

    server.start(function () {
        server.log([],'Server started at: ' + server.info.uri);
    });
});

var validateFunction = function (token, callback) {
    // Use a real strategy here to check if the token is valid
    if (token === 'abc456789') {
        callback(null, true, userCredentials);
    } else {
        callback(null, false, userCredentials);
    }
};
```

- `validateFunc` - (required) a token lookup and validation function with the signature `function (token, [request], callback)`
    - `token` - the auth token received from the client.
    - `request` - Optional request object. See below.
    - `callback` - a callback function with the signature `function (err, isValid, credentials)` where:
        - `err` - any error.
        - `isValid` - `true` if both the username was found and the password matched, otherwise `false`.
        - `credentials` - an object passed back to the plugin and which will become available in the `request`object as `request.auth.credentials`. Normally credentials are only included when `isValid`is `true`. This object can be only the token as in the example but is preferably all the info you need from the authenticated user
- `exposeRequest` - (optional / advanced) If set to `true` the `validateFunction`'s signature will be `function (token, request, callback)`. This can be usefull if you have plugins that expose certain functions/object to the `request` object and you want to use them in your `validateFunction`. Be aware that modifying the object is not recommended because this is the same object that you will use in the whole lifecycle. Also exposing functions/object to the `resuest` object during the validation is not recommended. Follow the `Hapi` standards whenever you can!

## Notes
 - 100% code coverage!
 - You can chain strategies when you give no `error` and `isValid = true` but leave the `credentials` empty.
 - If you have any problems and/or questions make a new [**issue**](https://github.com/Salesflare/hapi-auth-bearer-simple/issues).
 - If you want to contribute feel free to fork and add a pull request or again make an [**issue**](https://github.com/Salesflare/hapi-auth-bearer-simple/issues).
