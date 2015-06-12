'use strict';

// Based on https://github.com/hapijs/hapi-auth-basic/blob/master/lib/index.js

var Boom = require('boom');
var Hoek = require('hoek');

var internals = {};

internals.validateCallback = function (err, isValid, credentials, reply) {

    if (err) {
        return reply(Boom.unauthorized(err.message, 'bearerAuth'), {
            isValid: isValid,
            credentials: credentials
        }, null, {});
    }

    if (!isValid) {
        return reply(Boom.unauthorized('INVALID_AUTHORIZATION', 'bearerAuth', {
            isValid: isValid,
            credentials: credentials
        }), null, {});
    }

    if (!credentials) {
        return reply(Boom.unauthorized(null, 'bearerAuth', {
            isValid: isValid,
            credentials: credentials
        }), null, {});
    }

    credentials.token = internals.token;
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
                reply(Boom.unauthorized('NO_AUTHORIZATION_HEADER', 'bearerAuth'), null, {});
            } else {
                var headerParts = request.headers.authorization.split(' ');

                if (headerParts[0].toLowerCase() !== 'bearer') {
                    return reply(Boom.notAcceptable('Token should be given in the Authorization header in "Bearer [token]" form. Example: "Authorization: Bearer azertyuiop0123"'));
                }

                internals.token = headerParts[1];

                // use provided validate function to return
                if (settings.exposeRequest) {
                    settings.validateFunction(internals.token, request, function (err, isValid, credentials) {

                        internals.validateCallback(err, isValid, credentials, reply);
                    });
                } else {
                    settings.validateFunction(internals.token, function (err, isValid, credentials) {

                        internals.validateCallback(err, isValid, credentials, reply);
                    });
                }
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
