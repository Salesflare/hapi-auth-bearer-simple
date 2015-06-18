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
    invalidAuhtorizationHeader: 'NotBearer abc'
};


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

    it('Returns notAcceptable error if authorization header is not bearer', function (done) {

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

            var request = { method: 'GET',	url: '/login/testuser', headers: { Authorization: internals.invalidAuhtorizationHeader } };

            server.inject(request, function (res) {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(406);

                done();
            });
        });
    });
});
