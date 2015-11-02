'use strict';

// Based on https://github.com/hapijs/hapi-auth-basic/blob/master/lib/index.js

const Boom = require('boom');
const Hoek = require('hoek');

const internals = {};

internals.validateCallback = function (err, isValid, credentials, token, reply) {

    if (err) {
        return reply(Boom.unauthorized(err.message, 'bearerAuth'), {
            isValid: isValid,
            credentials: credentials
        }, null, {});
    }

    if (!isValid) {
        return reply(Boom.unauthorized(null, 'bearerAuth', {
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

    credentials.token = token;

    return reply.continue({
        credentials: credentials
    });
};

internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing bearerAuthentication strategy options');
    Hoek.assert(typeof options.validateFunction === 'function', 'options.validateFunc must be a valid function in bearerAuthentication scheme');

    const settings = Hoek.clone(options);

    const scheme = {
        authenticate: (request, reply) => {

            if (!request.headers.authorization ||
                request.headers.authorization === undefined) {
                return reply(Boom.unauthorized('NO_AUTHORIZATION_HEADER', 'bearerAuth'), null, {});
            }

            const headerParts = request.headers.authorization.split(' ');

            if (headerParts[0].toLowerCase() !== 'bearer') {
                return reply(Boom.notAcceptable('Token should be given in the Authorization header in "Bearer [token]" form. Example: "Authorization: Bearer azertyuiop0123"'));
            }

            const token = headerParts[1];

            // use provided validate function to return
            if (settings.exposeRequest) {
                settings.validateFunction(token, request, (err, isValid, credentials) => {

                    internals.validateCallback(err, isValid, credentials, token, reply);
                });
            }
            else {
                settings.validateFunction(token, (err, isValid, credentials) => {

                    internals.validateCallback(err, isValid, credentials, token, reply);
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
