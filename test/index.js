'use strict';

var Code = require('code');
var Hapi = require('hapi');
var Lab = require('lab');

var lab = exports.lab = Lab.script();
var it = lab.it;
var expect = Code.expect;

var internals = {
    validCredentials: {
        email: 'test@test.com',
        token: 'abc'
    },
    validUser: {
        email: 'test@test.com'
    },
    token: 'abc',
    authorizationHeader: 'Bearer abc',
    invalidAuthorizationHeader: 'NotBearer abc',
    mockAuthScheme: {
        register: function (server, options, next) {

            server.auth.scheme('mockAuth', function (svr, opts) {

                return {
                    authenticate: function (request, reply) {

                        opts.authSchemeCalled = true;
                        reply.continue({
                            credentials: {}
                        });
                    }
                };
            });
            next();
        }
    }
};

internals.mockAuthScheme.register.attributes = { name: 'mock-auth', version: '1.0.0' };


lab.experiment('Integration', function () {

    it('authenticates a request', function (done) {

        var validFunc = function (token, callback) {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: function (request, reply) {

                        return reply(request.auth.credentials);
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser',	headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.exist();
                expect(res.result).to.deep.equal(internals.validCredentials);
                done();
            });
        });
    });

    it('exposes the request object', function (done) {

        var validFunc = function (token, request, callback) {

            expect(token).to.exist();
            expect(request).to.exist();
            expect(request).to.be.an.object();
            expect(request.path).to.equal('/login/testuser');

            return callback(null, token === internals.token, internals.validUser);
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, {
                validateFunction: validFunc,
                exposeRequest: true
            });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: function (request, reply) {

                        return reply(request.auth.credentials);
                    }
                }
            });

            var request = { method: 'GET', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.exist();
                expect(res.result).to.deep.equal(internals.validCredentials);
                done();
            });
        });
    });

    it('Returns unAuthorized error if validFunction throws error', function (done) {

        var validFunc = function (token, callback) {

            expect(token).to.exist();

            return callback('401', false, null);
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser',	headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns unAuthorized error if validFunction determines token is not valid', function (done) {

        var validFunc = function (token, callback) {

            expect(token).to.exist();

            return callback(null, token !== internals.token, null);
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser',	headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns unAuthorized error if validFunction does not return credentials', function (done) {

        var validFunc = function (token, callback) {

            expect(token).to.exist();

            return callback(null, token === internals.token, null);
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser',	headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns unAuthorized error if no authorization header', function (done) {

        var validFunc = function (token, callback) {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser' };

            server.inject(request, function (res) {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns unAuthorized error if authorization header is undefined', function (done) {

        var validFunc = function (token, callback) {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: undefined } };

            server.inject(request, function (res) {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns unAuthorized error if authorization header is not bearer', function (done) {

        var validFunc = function (token, callback) {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        var server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.invalidAuthorizationHeader } };

            server.inject(request, function (res) {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('should try next strategy if auth mode is "try" and authorization header is missing', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {} });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'try',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser' };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(mockOptions.authSchemeCalled).to.equal(true);

                done();
            });
        });
    });

    it('should try next strategy if auth mode is "try" and authorization header does not have bearer prefix', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {} });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'try',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.invalidAuthorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(mockOptions.authSchemeCalled).to.equal(true);

                done();
            });
        });
    });

    it('should try next strategy if auth mode is "try" and authorization header is invalid', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {

                callback(null, false);
            } });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'try',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(mockOptions.authSchemeCalled).to.equal(true);

                done();
            });
        });
    });

    it('should try next strategy if auth mode is "try" and validation returns error', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {

                callback(new Error('Canned error'), false);
            } });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'try',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(mockOptions.authSchemeCalled).to.equal(true);

                done();
            });
        });
    });

    it('should try next strategy if auth mode is "try" and credentials are missing', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {

                callback(null, true);
            } });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'try',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(mockOptions.authSchemeCalled).to.equal(true);

                done();
            });
        });
    });

    it('should try next strategy if auth mode is "optional" and authorization header is missing', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {} });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'optional',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser' };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(mockOptions.authSchemeCalled).to.equal(true);

                done();
            });
        });
    });

    it('should try next strategy if auth mode is "optional" and authorization header does not have bearer prefix', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {} });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'optional',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.invalidAuthorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(mockOptions.authSchemeCalled).to.equal(true);

                done();
            });
        });
    });

    it('should NOT try next strategy if auth mode is "optional" and authorization header is invalid', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {

                callback(null, false);
            } });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'optional',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(401);
                expect(mockOptions.authSchemeCalled).to.equal(false);

                done();
            });
        });
    });

    it('should NOT try next strategy if auth mode is "optional" and validation returns error', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {

                callback(new Error('Canned error'), false);
            } });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'optional',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(401);
                expect(mockOptions.authSchemeCalled).to.equal(false);

                done();
            });
        });
    });

    it('should NOT try next strategy if auth mode is "optional" and credentials are missing', function (done) {

        var mockOptions = { authSchemeCalled: false };

        var server = new Hapi.Server();
        server.connection();

        server.register([internals.mockAuthScheme, require('../lib/')], function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', { validateFunction: function (token, callback) {

                callback(null, true);
            } });
            server.auth.strategy('mock', 'mockAuth', mockOptions);

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: {
                        mode: 'optional',
                        strategies: ['default', 'mock']
                    },
                    handler: function (request, reply) {

                        return reply('ok');
                    }
                }
            });

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, function (res) {

                expect(res.statusCode).to.equal(401);
                expect(mockOptions.authSchemeCalled).to.equal(false);

                done();
            });
        });
    });
});
