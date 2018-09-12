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

    it('authenticates a request with Authorization header', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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
                    expect(res.result).to.equal(internals.validCredentials);
                    return resolve();
                });
            });
        });
    });

    it('authenticates a request with access_token query param', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

            return server.register(require('../lib/'), (err) => {

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

                const request = { method: 'POST', url: '/login/testuser?access_token=' + internals.token };

                return server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.exist();
                    expect(res.result).to.equal(internals.validCredentials);
                    return resolve();
                });
            });
        });
    });

    it('exposes the request object', () => {

        const validFunc = function (token, callback) {

            expect(token).to.exist();
            expect(this).to.exist();
            expect(this).to.be.an.object();
            expect(this.path).to.equal('/login/testuser');

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

            return server.register(require('../lib/'), (err) => {

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

                return server.inject(request, (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.exist();
                    expect(res.result).to.equal(internals.validCredentials);
                    return resolve();
                });
            });
        });
    });

    it('Returns unAuthorized error if validFunction throws error', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(new Error('fail'), false, null);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

            return server.register(require('../lib/'), (err) => {

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

                return server.inject(request, (res) => {

                    expect(res.result).to.exist();
                    expect(res.statusCode).to.equal(500);

                    return resolve();
                });
            });
        });
    });

    it('Returns unAuthorized error if validFunction does not return credentials', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, true, null);
        };

        const server = new Hapi.Server({ debug: false });
        server.connection();

        return new Promise((resolve) => {

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

                    return resolve();
                });
            });
        });
    });

    it('Returns unAuthorized error if validFunction determines token is not valid', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token !== internals.token, null);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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

                    return resolve();
                });
            });
        });
    });

    it('Returns unAuthorized error if no authorization header', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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

                    return resolve();
                });
            });
        });
    });

    it('Returns unAuthorized error if authorization header is undefined', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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

                    return resolve();
                });
            });
        });
    });

    it('Returns unAuthorized error if authorization header is not bearer', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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

                    return resolve();
                });
            });
        });
    });

    it('returns a reply on failed optional auth', () => {

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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

                    return resolve();
                });
            });
        });
    });

    it('errors on success optional auth but no valid credentials', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, true, null);
        };

        const server = new Hapi.Server({ debug: false });
        server.connection();

        return new Promise((resolve) => {

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

                    return resolve();
                });
            });
        });
    });

    it('returns a reply on failed try auth', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, false, null);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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

                    return resolve();
                });
            });
        });
    });

    it('cannot add a route that has payload validation required', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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
                return resolve();
            });
        });
    });

    it('cannot add a route that has payload validation optional', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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
                return resolve();
            });
        });
    });

    it('can add a route that has payload validation as none', () => {

        const validFunc = (token, callback) => {

            expect(token).to.exist();

            return callback(null, token === internals.token, internals.validUser);
        };

        const server = new Hapi.Server();
        server.connection();

        return new Promise((resolve) => {

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
                return resolve();
            });
        });
    });
});
