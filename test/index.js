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


lab.experiment('hapi-auth-bearer-simple', () => {

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
                method: 'POST',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply(request.auth.credentials);
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

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
                method: 'POST',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply(request.auth.credentials);
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

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

            return callback(new Error('fail'), false, null);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'POST',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(500);

                done();
            });
        });
    });

    it('Returns unAuthorized error if validFunction does not return credentials', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, true, null);
        };

        const server = new Hapi.Server({ debug: false });
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', true, { validateFunction: validFunc });

            server.route({
                method: 'POST',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(500);

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
                method: 'POST',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);
                expect(res.payload.message).to.be.undefined();

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
                method: 'POST',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser' };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);
                expect(res.payload.message).to.be.undefined();

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
                method: 'POST',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser', headers: { Authorization: undefined } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);
                expect(res.payload.message).to.be.undefined();

                done();
            });
        });
    });

    it('Returns unAuthorized error if authorization header is not bearer', (done) => {

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
                method: 'POST',
                path: '/login/{user}',
                config: {
                    auth: 'default',
                    handler: (request, reply) => {

                        return reply('ok');
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser', headers: { Authorization: internals.invalidAuhtorizationHeader } };

            server.inject(request, (res) => {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);
                expect(res.payload.message).to.be.undefined();

                done();
            });
        });
    });

    it('returns a reply on failed optional auth', (done) => {

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', 'required', { validateFunction: () => {} });
            server.route({
                method: 'POST',
                path: '/login/{user}',
                handler: (request, reply) => {

                    return reply('ok');
                },
                config: {
                    auth: {
                        mode: 'optional'
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser' };

            server.inject(request, (res) => {

                expect(res.result).to.equal('ok');

                done();
            });
        });
    });

    it('errors on success optional auth but no valid credentials', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, true, null);
        };

        const server = new Hapi.Server({ debug: false });
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', 'required', { validateFunction: validFunc });
            server.route({
                method: 'POST',
                path: '/login/{user}',
                handler: (request, reply) => {

                    return reply('ok');
                },
                config: {
                    auth: {
                        mode: 'optional'
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };

            server.inject(request, (res) => {

                expect(res.result.statusCode).to.equal(500);

                done();
            });
        });
    });

    it('returns a reply on failed try auth', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, false, null);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', 'required', { validateFunction: validFunc });
            server.route({
                method: 'POST',
                path: '/login/{user}',
                handler: (request, reply) => {

                    return reply('ok');
                },
                config: {
                    auth: {
                        mode: 'try'
                    }
                }
            });

            const request = { method: 'POST', url: '/login/testuser', headers: { Authorization: internals.authorizationHeader } };


            server.inject(request, (res) => {

                expect(res.result).to.equal('ok');

                done();
            });
        });
    });

    it('cannot add a route that has payload validation required', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', 'required', { validateFunction: validFunc });

            const fn = () => {

                server.route({
                    method: 'POST',
                    path: '/',
                    handler: (request, reply) => {

                        return reply('ok');
                    },
                    config: {
                        auth: {
                            mode: 'required',
                            payload: 'required'
                        }
                    }
                });
            };

            expect(fn).to.throw('Payload validation can only be required when all strategies support it in /');
            done();
        });
    });

    it('cannot add a route that has payload validation optional', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', 'required', { validateFunction: validFunc });

            const fn = () => {

                server.route({
                    method: 'POST',
                    path: '/',
                    handler: (request, reply) => {

                        return reply('ok');
                    },
                    config: {
                        auth: {
                            mode: 'required',
                            payload: 'optional'
                        }
                    }
                });
            };

            expect(fn).to.throw('Payload authentication requires at least one strategy with payload support in /');
            done();
        });
    });

    it('can add a route that has payload validation as none', (done) => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        server.register(require('../lib/'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'bearerAuth', 'required', { validateFunction: validFunc });

            const fn = () => {

                server.route({
                    method: 'POST',
                    path: '/',
                    handler: (request, reply) => {

                        return reply('ok');
                    },
                    config: {
                        auth: {
                            mode: 'required',
                            payload: false
                        }
                    }
                });
            };

            expect(fn).to.not.throw();
            done();
        });
    });
});
