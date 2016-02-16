'use strict';

// Based on https://github.com/hapijs/hapi-auth-basic/blob/master/lib/index.js

const Boom = require('boom');
const Hoek = require('hoek');

const internals = {};

internals.validateCallback = function (err, isValid, credentials, token, reply) {

    credentials = credentials || null;

    if (err) {
        return reply(err, null, { credentials: credentials });
    }

    if (!isValid) {
        return reply(Boom.unauthorized(null, 'bearerAuth', {
            isValid: isValid,
            credentials: credentials
        }), null, { credentials: credentials });
    }

    if (!credentials ||
        typeof credentials !== 'object') {

        return reply(Boom.badImplementation('Bad credentials object received for bearerAuth auth validation'));
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

                return reply(Boom.unauthorized(null, 'bearerAuth'), null, {});
            }

            const headerParts = request.headers.authorization.split(' ');

            if (headerParts[0].toLowerCase() !== 'bearer') {
                return reply(Boom.unauthorized(null, 'bearerAuth'));
            }

            const token = headerParts[1];

            // use provided validate function to return
            if (settings.exposeRequest) {
                return settings.validateFunction(token, request, (err, isValid, credentials) => {

                    return internals.validateCallback(err, isValid, credentials, token, reply);
                });
            }

            return settings.validateFunction(token, (err, isValid, credentials) => {

                return internals.validateCallback(err, isValid, credentials, token, reply);
            });
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
