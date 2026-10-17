var jwt = require('jsonwebtoken');
var assert = require('assert');

var restifyjwt = require('../lib');
const errors = require('restify-errors');

describe('Node 24 module loading', function () {
  it('loads without importing Restify at runtime', function () {
    const script = `
      const Module = require('module');
      const originalLoad = Module._load;
      Module._load = function (name) {
        if (name === 'restify') throw new Error('Unexpected Restify runtime import');
        return originalLoad.apply(this, arguments);
      };
      if (typeof require(process.argv[1]) !== 'function') process.exit(1);
    `;
    require('child_process').execFileSync(process.execPath, ['-e', script, require.resolve('../lib')], { stdio: 'pipe' });
  });
});

describe('Node 24 real HTTP authentication', function () {
  const restify = require('restify');
  const http = require('http');
  const secret = 'synthetic-node24-test-secret';
  let server;

  beforeEach(function (done) {
    server = restify.createServer({ strictNext: true });
    server.listen(0, '127.0.0.1', done);
  });

  afterEach(function (done) {
    server.close(done);
  });

  const get = function (path, token, check, done) {
    const headers = token ? { authorization: 'Bearer ' + token } : {};
    const pending = http.get({ hostname: '127.0.0.1', port: server.address().port, path, headers }, function (response) {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', function () {
        try {
          check(response, JSON.parse(body));
          done();
        } catch (error) {
          done(error);
        }
      });
    });
    pending.setTimeout(2000, function () { pending.destroy(new Error('Synthetic HTTP request timed out')); });
    pending.on('error', done);
  };

  const mountProtected = function (options) {
    server.use(restifyjwt(Object.assign({ secret, algorithms: ['HS256'] }, options)));
    server.get('/protected', function protectedHandler(req, res, next) {
      res.send({ id: req.user.id });
      return next();
    });
  };

  it('accepts a valid token and exposes only the expected identity', function (done) {
    mountProtected();
    get('/protected', jwt.sign({ id: 7 }, secret), function (response, body) {
      assert.strictEqual(response.statusCode, 200);
      assert.deepStrictEqual(body, { id: 7 });
    }, done);
  });

  ['missing', 'expired', 'invalid signature', 'revoked'].forEach(function (mode) {
    it('rejects ' + mode + ' credentials with HTTP 401', function (done) {
      mountProtected({ isRevoked: function (req, payload, callback) { callback(null, mode === 'revoked'); } });
      const token = mode === 'missing' ? undefined : jwt.sign(
        mode === 'expired' ? { id: 7, exp: 1 } : { id: 7 },
        mode === 'invalid signature' ? 'another-synthetic-secret' : secret
      );
      get('/protected', token, function (response, body) {
        assert.strictEqual(response.statusCode, 401);
        assert.strictEqual(body.code, mode === 'revoked' ? 'Unauthorized' : 'InvalidCredentials');
        assert.strictEqual(body.id, undefined);
      }, done);
    });
  });

  it('preserves a public unless path without an authorization header', function (done) {
    server.use(restifyjwt({ secret }).unless({ path: ['/public'] }));
    server.get('/public', function publicHandler(req, res, next) {
      assert.strictEqual(req.user, undefined);
      res.send({ public: true });
      return next();
    });

    get('/public', undefined, function (response, body) {
      assert.strictEqual(response.statusCode, 200);
      assert.deepStrictEqual(body, { public: true });
    }, done);
  });
});

describe('failure tests', function () {
  var req = {};
  var res = {};

  it('should throw if options not sent', function() {
    try {
      restifyjwt();
    } catch(e) {
      assert.ok(e);
      assert.equal(e.message, 'secret should be set');
    }
  });

  it('should throw if no authorization header and credentials are required', function() {
    restifyjwt({secret: 'shhhh', credentialsRequired: true})(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.message, 'No authorization token was found');
    });
  });

  it('support unless skip', function() {
    req.originalUrl = '/index.html';
    restifyjwt({secret: 'shhhh'}).unless({path: '/index.html'})(req, res, function(err) {
      assert.ok(!err);
    });
  });

  it('should skip on CORS preflight', function() {
    var corsReq = {};
    corsReq.method = 'OPTIONS';
    corsReq.headers = {
      'access-control-request-headers': 'sasa, sras,  authorization'
    };
    restifyjwt({secret: 'shhhh'})(corsReq, res, function(err) {
      assert.ok(!err);
    });
  });

  it('should throw if authorization header is malformed', function() {
    req.headers = {};
    req.headers.authorization = 'wrong';
    restifyjwt({secret: 'shhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.message, 'Format is Authorization: Bearer [token]');
    });
  });

  it('should throw if authorization header is not Bearer', function() {
    req.headers = {};
    req.headers.authorization = 'Basic foobar';
    restifyjwt({secret: 'shhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.body.code, 'InvalidCredentials');
    });
  });

  it('should throw if authorization header is not well-formatted jwt', function() {
    req.headers = {};
    req.headers.authorization = 'Bearer wrongjwt';
    restifyjwt({secret: 'shhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.body.code, 'InvalidCredentials');
    });
  });

  it('should throw if authorization header is not valid jwt', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyjwt({secret: 'different-shhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.body.code, 'InvalidCredentials');
      assert.equal(err.cause().message, 'invalid signature');
    });
  });

  it('should throw if audience is not expected', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar', aud: 'expected-audience'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyjwt({secret: 'shhhhhh', audience: 'not-expected-audience'})(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.body.code, 'InvalidCredentials');
      assert.equal(err.cause().message, 'jwt audience invalid. expected: not-expected-audience');
    });
  });

  it('should throw if token is expired', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar', exp: 1382412921 }, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyjwt({secret: 'shhhhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.body.code, 'InvalidCredentials');
      assert.equal(err.cause().message, 'jwt expired');
    });
  });

  it('should throw if token issuer is wrong', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar', iss: 'http://foo' }, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyjwt({secret: 'shhhhhh', issuer: 'http://wrong'})(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.body.code, 'InvalidCredentials');
      assert.equal(err.cause().message, 'jwt issuer invalid. expected: http://wrong');
    });
  });

  it('should use errors thrown from custom getToken function', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar'}, secret);

    function getTokenThatThrowsError() {
      throw new errors.InvalidCredentialsError('Invalid token!');
    }

    restifyjwt({
      secret: 'shhhhhh',
      getToken: getTokenThatThrowsError
    })(req, res, function(err) {
      assert.ok(err);
      assert.equal(err.message, 'Invalid token!');
    });
  });


  it('should throw error when signature is wrong', function() {
      var secret = "shhh";
      var token = jwt.sign({foo: 'bar', iss: 'http://www'}, secret);
      // manipulate the token
      var newContent = new Buffer("{foo: 'bar', edg: 'ar'}").toString('base64');
      var splitetToken = token.split(".");
      splitetToken[1] = newContent;
      var newToken = splitetToken.join(".");

      // build request
      req.headers = [];
      req.headers.authorization = 'Bearer ' + newToken;
      restifyjwt({secret: secret})(req,res, function(err) {
        assert.ok(err);
        assert.equal(err.body.code, 'InvalidCredentials');
        assert.equal(err.cause().message, 'invalid token');
      });
  });

});

describe('work tests', function () {
  var req = {};
  var res = {};

  it('should work if authorization header is valid jwt', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyjwt({secret: secret})(req, res, function() {
      assert.equal('bar', req.user.foo);
    });
  });

  it('should work if authorization header is valid with a buffer secret', function() {
    var secret = new Buffer('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64');
    var token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyjwt({secret: secret})(req, res, function() {
      assert.equal('bar', req.user.foo);
    });
  });

  it('should set userProperty if option provided', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyjwt({secret: secret, userProperty: 'auth'})(req, res, function() {
      assert.equal('bar', req.auth.foo);
    });
  });

  it('should work if no authorization header and credentials are not required', function() {
    req = {};
    restifyjwt({secret: 'shhhh', credentialsRequired: false})(req, res, function(err) {
      assert(typeof err === 'undefined');
    });
  });

  it('should work if token is expired and credentials are not required', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar', exp: 1382412921}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyjwt({ secret: secret, credentialsRequired: false })(req, res, function(err) {
      assert(typeof err === 'undefined');
      assert(typeof req.user === 'undefined')
    });
  });

  it('should not work if no authorization header', function() {
    req = {};
    restifyjwt({ secret: 'shhhh' })(req, res, function(err) {
      assert(typeof err !== 'undefined');
    });
  });

  it('should work with a custom getToken function', function() {
    var secret = 'shhhhhh';
    var token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.query = {};
    req.query.token = token;

    function getTokenFromQuery(req) {
      return req.query.token;
    }

    restifyjwt({
      secret: secret,
      getToken: getTokenFromQuery
    })(req, res, function() {
      assert.equal('bar', req.user.foo);
    });
  });

  it('should work with a secretCallback function that accepts header argument', function() {
    var secret = 'shhhhhh';
    var secretCallback = function(req, headers, payload, cb) {
      assert.equal(headers.alg, 'HS256');
      assert.equal(payload.foo, 'bar');
      process.nextTick(function(){ return cb(null, secret); });
    };
    var token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyjwt({secret: secretCallback})(req, res, function() {
      assert.equal('bar', req.user.foo);
    });
  });
});
