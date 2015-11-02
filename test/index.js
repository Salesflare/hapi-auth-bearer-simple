'use strict';

const Code = require('code');
const Hapi = require('hapi');
const Lab = require('lab');

const lab = exports.lab = Lab.script();
const it = lab.it;
const expect = Code.expect;

const internals = {
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


lab.experiment('Integration', () => {

    it('authenticates a request', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply(request.auth.credentials);
                    }
                }
            });

            const request = { method: 'GET', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.exist();
                expect(res.result).to.deep.equal(internals.validCredentials);
                done();
            });
        });
    });

    it('exposes the request object', (done) => {

        const validFunc = function (token, request, callback) {

            expect(token).to.exist();
            expect(request).to.exist();
            expect(request).to.be.an.object();
            expect(request.path).to.equal('/login/testuser');

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

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
                    handler: (request, reply) => {

                        return reply(request.auth.credentials);
                    }
                }
            });

            const request = { method: 'GET', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.exist();
                expect(res.result).to.deep.equal(internals.validCredentials);
                done();
            });
        });
    });

    it('Returns unAuthorized error if validFunction throws error', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback('401', false, null);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'GET', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns unAuthorized error if validFunction determines token is not valid', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token !== internals.token, null);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'GET', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns unAuthorized error if validFunction does not return credentials', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, null);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'GET', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns unAuthorized error if no authorization header', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'GET', url: '/login/testuser' };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns unAuthorized error if authorization header is undefined', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'GET', url: '/login/testuser', headers: { Authorization: undefined } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);

                done();
            });
        });
    });

    it('Returns notAcceptable error if authorization header is not bearer', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'GET',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'GET', url: '/login/testuser', headers: { Authorization: internals.invalidAuhtorizationHeader } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(406);

                done();
            });
        });
    });
});
