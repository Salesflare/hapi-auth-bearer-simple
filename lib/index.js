'use strict';

// Based on https://github.com/hapijs/hapi-auth-basic/blob/master/lib/index.js

var Boom = require('boom');
var Hoek = require('hoek');

var internals = {};

internals.validateCallback = function (err, isValid, credentials, token, request, reply) {

    var isTry = request.auth.mode === 'try';
    var message = null;
    if (err) {
        if (!isTry) {
            message = err.message;
        }

        return reply(Boom.unauthorized(message, 'bearerAuth'), {
            isValid: isValid,
            credentials: credentials
        }, null, {});
    }

    if (!isValid) {
        if (!isTry) {
            message = 'INVALID';
        }

        return reply(Boom.unauthorized(message, 'bearerAuth', {
            isValid: isValid,
            credentials: credentials
        }), null, {});
    }

    if (!credentials) {
        if (!isTry) {
            message = 'MISSING_CREDENTIALS';
        }

        return reply(Boom.unauthorized(message, 'bearerAuth', {
            isValid: isValid,
            credentials: credentials
        }), null, {});
    }

    credentials.token = token;

    return reply.continue({
        credentials: credentials
    });
};

internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing bearerAuthentication strategy options');
    Hoek.assert(typeof options.validateFunction === 'function', 'options.validateFunc must be a valid function in bearerAuthentication scheme');

    var settings = Hoek.clone(options);

    var scheme = {
        authenticate: function (request, reply) {

            if (!request.headers.authorization ||
                request.headers.authorization === undefined) {
                return reply(Boom.unauthorized(null, 'bearerAuth'), null, {});
            }

            var headerParts = request.headers.authorization.split(' ');

            if (headerParts[0].toLowerCase() !== 'bearer') {
                return reply(Boom.unauthorized(null, 'bearerAuth'));
            }

            var token = headerParts[1];

            // use provided validate function to return
            if (settings.exposeRequest) {
                settings.validateFunction(token, request, function (err, isValid, credentials) {

                    internals.validateCallback(err, isValid, credentials, token, request, reply);
                });
            } else {
                settings.validateFunction(token, function (err, isValid, credentials) {

                    internals.validateCallback(err, isValid, credentials, token, request, reply);
                });
            }
        }
    };

    return scheme;
};

exports.register = function (server, options, next) {

    server.auth.scheme('bearerAuth', internals.implementation);

    server.log(['hapi-auth-bearer-simple'], 'bearerAuth plugin registered');

    return next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};
