'use strict';

var Code = require('code');
var Hapi = require('hapi');
var Lab = require('lab');

var lab = exports.lab = Lab.script();
var it = lab.it;
var expect = Code.expect;

lab.experiment('Integration', function () {
   it('authenticates a request', function (done) {
      var server = new Hapi.Server();
      server.connection();

      server.register(require('../'), function (err) {
         expect(err).to.not.exist();

         server.auth.strategy('default', 'bearerAuth', true, {
            validateFunction: function (token, callback) {
               var validated_user = {
                  email: 'test@test.com'
               };
               return callback(null, token === 'abc', validated_user);
            }
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

         server.inject({
            method: 'GET',
            url: '/login/testuser',
            headers: {
               Authorization: 'Bearer abc'
            }
         }, function (res) {
            expect(res.statusCode).to.equal(200);
            expect(res.result).to.deep.equal({
               email: 'test@test.com',
               token: 'abc'
            });


            done();
         });

      });
   });
});