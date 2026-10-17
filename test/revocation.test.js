var jwt = require('jsonwebtoken');
var assert = require('assert');

var restifyjwt = require('../lib');

describe('revoked jwts', function(){
  var secret = 'shhhhhh';

  var revoked_id = '1234';

  var middleware = restifyjwt({
    secret: secret,
    isRevoked: function(req, payload, done){
      done(null, payload.jti && payload.jti === revoked_id);
    }
  });

  it('Node 24 revocation returns an operational 401 without a Restify monkey patch', function(done) {
    const errors = require('restify-errors');
    const token = jwt.sign({ jti: revoked_id, foo: 'bar' }, secret);
    const req = { headers: { authorization: 'Bearer ' + token } };
    let nextCalls = 0;

    middleware(req, {}, function(error) {
      nextCalls += 1;
      assert.ok(error instanceof errors.UnauthorizedError);
      assert.strictEqual(error.statusCode, 401);
      assert.strictEqual(error.body.code, 'Unauthorized');
      assert.strictEqual(error.message, 'The token has been revoked.');
      assert.strictEqual(req.user, undefined);
      assert.strictEqual(nextCalls, 1);
      done();
    });
  });

  it('should throw if token is revoked', function(){
    var req = {};
    var res = {};
    var token = jwt.sign({ jti: revoked_id, foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;

    middleware(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.body.code, 'Unauthorized');
      assert.equal(err.message, 'The token has been revoked.');
    });
  });

  it('should work if token is not revoked', function(){
    var req = {};
    var res = {};
    var token = jwt.sign({ jti: '1233', foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;

    middleware(req, res, function() {
      assert.equal('bar', req.user.foo);
    });
  });

  it('should throw if error occurs checking if token is revoked', function(){
    var req = {};
    var res = {};
    var token = jwt.sign({ jti: revoked_id, foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;

    restifyjwt({
      secret: secret,
      isRevoked: function(req, payload, done){
        done(new Error('An error ocurred'));
      }
    })(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.message, 'An error ocurred');
    });
  });
});
