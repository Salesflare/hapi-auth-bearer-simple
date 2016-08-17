'use strict';

// Based on https://github.com/hapijs/hapi-auth-basic/blob/master/lib/index.js

const Boom = require('boom');
const Hoek = require('hoek');

const internals = {};

internals.validateCallback = (err, isValid, credentials, token, reply) => {

    credentials = credentials || null;

    if (err) {
        return reply(err, null, { credentials });
    }

    if (!isValid) {
        return reply(Boom.unauthorized(null, 'bearerAuth', {
            isValid,
            credentials
        }), null, { credentials });
    }

    if (!credentials ||
        typeof credentials !== 'object') {

        return reply(Boom.badImplementation('Bad credentials object received for bearerAuth auth validation'));
    }

    credentials.token = token;

    return reply.continue({
        credentials
    });
};

internals.implementation = (server, options) => {

    Hoek.assert(options, 'Missing bearerAuthentication strategy options');
    Hoek.assert(typeof options.validateFunction === 'function', 'options.validateFunc must be a valid function in bearerAuthentication scheme');

    const settings = Hoek.clone(options);

    const scheme = {
        authenticate: (request, reply) => {

            let token = '';

            if (request.query.access_token) {
                token = request.query.access_token;
                delete request.query.access_token;
            }
            else if (request.headers.authorization && request.headers.authorization !== undefined) {
                const headerParts = request.headers.authorization.split(' ');

                if (headerParts[0].toLowerCase() !== 'bearer') {
                    return reply(Boom.unauthorized(null, 'bearerAuth'));
                }

                token = headerParts[1];
            }
            else {
                return reply(Boom.unauthorized(null, 'bearerAuth'), null, {});
            }

            // use provided validate function to return
            if (settings.exposeRequest) {
                return settings.validateFunction.call(request, token, (err, isValid, credentials) => {

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

exports.register = (server, options, next) => {

    server.auth.scheme('bearerAuth', internals.implementation);

    server.log(['hapi-auth-bearer-simple'], 'bearerAuth plugin registered');

    return next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};
