
describe('Test RBAC', function () {

  const request = require('supertest');
  const koa = require('koa');
  const RBAC = require('rbac-a');
  const JsonProvider = require('rbac-a/lib/providers/json');

  const middleware = require('../rbac');

  const RULES = {
    roles: {
      'guest': {
        //name: 'Guest',
        permissions: ['foo']
      },
      'reader': {
        //name: 'Reader',
        permissions: ['read'],
        inherited: ['guest']
      },
      'writer': {
        //name: 'Writer',
        permissions: ['create'],
        inherited: ['reader']
      },
      'editor': {
        //name: 'Editor',
        permissions: ['update'],
        inherited: ['reader']
      },
      'director': {
        //name: 'Director',
        permissions: ['delete'],
        inherited: ['editor']
      },
      'admin': {
        //name: 'Administrator',
        permissions: ['manage']
      },

      'cyclic1': {
        permissions: ['crc1'],
        inherited: ['cyclic2']
      },
      'cyclic2': {
        permissions: ['crc2'],
        inherited: ['cyclic1']
      },

      'special': {
        // note: no permissions
      }
    },
    users: {
      'bart': ['guest', 'reader'],
      'marge': ['editor'],
      'homer': ['admin', 'director'],
      'burns': ['admin'],
      'phsycho bob': ['cyclic1'],
      'ralph': ['special', 'learned']  // unknown role 'learned'!
    }
  };

  const MIDDLEWARE_OPTIONS = {
    rbac: new RBAC(new JsonProvider(RULES))
  };


  function validate(useRbacMiddleware, identity, validateionMiddleware, status, accept) {
    const app = koa();
    var rbac;

    if (identity) {
      app.use(function * (next) {
        this.user = identity;
        yield next;
      });
    }

    if (useRbacMiddleware) {
      app.use(middleware(useRbacMiddleware));
    }
    if (Array.isArray(validateionMiddleware)) {
      validateionMiddleware.forEach(function (middleware) {
        app.use(middleware);
      });
    } else {
      app.use(validateionMiddleware);
    }

    app.use(function * () {
      this.status = 200;
    });

    return new Promise(function (resolve, reject) {
      const error = new Error();

      request(app.listen())
      .get('/')
      .set('Accept', accept)
      .expect(status, function (err, res) {
        if (err) {
          error.message = err.message;
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }


  it('should return middleware with default options', function () {
    middleware().should.be.instanceOf(Function);
  });

  it('should be a valid RBAC-A instance', function () {
    [
      undefined, null, false, true, 0, NaN, Infinity, '', 'hello', [], {},
      function () {}, function * () {}, function RBAC() {},
      /./, new Date()
    ].forEach(function (rbac) {
      +function () { middleware({ rbac: rbac }); }.should.throw('Invalid RBAC instance');
    });
  });

  it('should be a valid identity function', function () {
    [
      undefined, null, false, true, 0, NaN, Infinity, '', 'hello', [], {},
      /./, new Date()
    ].forEach(function (rbac) {
      +function () { middleware({ identity: rbac }); }.should.throw('Invalid identity function');
    });
  });

  it('should accept valid RBAC-A instance', function () {
    const rbac = new RBAC(new JsonProvider(RULES));
    const options = {
      rbac: rbac
    };

    middleware(options);

    options.rbac.should.equal(rbac);
  });

  it('should accept valid identity function', function () {
    const identity = function () {};
    const options = {
      identity: identity
    };

    middleware(options);

    options.identity.should.equal(identity);
  });

  it('should allow / deny', function () {
    this.timeout(1000);

    return Promise.all([
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.allow(['read']), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.allow(['update']), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.allow(['create', 'update']), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.allow('create, update'), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.allow(['manage']), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.allow(['foo']), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.allow(['read']), 403, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.allow('read && update'), 200, 'text/html'),

      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.allow('read && update'), 200, 'text/html'),

      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read']), 403, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read']), 403, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.deny(['read', 'update']), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.deny(['read', 'manage']), 403, 'text/html'),

      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.check({ 'allow': 'read' }), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.check({ 'deny': ['read', 'update'] }), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.check({ 'deny': ['read', 'manage'] }), 403, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.check({ 'allow': ['update'], 'deny': ['read'] }), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.check({ 'allow': ['manage'], 'deny': ['read'] }), 403, 'text/html'),

      // redirect
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.allow('read', null, '/foo'), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.allow(['update'], null, '/foo'), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.allow('manage', null, '/foo'), 302, 'text/html'),

      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read'], null, '/foo'), 302, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read'], null, '/foo'), 302, 'application/json'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.deny(['read', 'update'], null, '/foo'), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read'], null, '/foo'), 302, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read'], null, '/foo'), 302, 'application/json'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.deny(['read', 'manage'], null, '/foo'), 302, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.deny(['read', 'manage'], null, '/foo'), 302, 'application/json'),

      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.check({ 'allow': ['manage'], 'deny': ['read'] }, null, '/foo'), 302, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.check({ 'allow': ['manage'], 'deny': ['read'] }, null, '/foo'), 302, 'application/json '),
    ]);
  });


  it('should allow / deny if no middleware', function () {
    this.timeout(1000);

    return Promise.all([
      validate(false, null, middleware.allow('read'), 200, 'text/html'),
      validate(false, 'bart', middleware.allow(['manage']), 200, 'text/html'),
      validate(false, 'burns', middleware.allow(['read']), 200, 'text/html'),

      validate(false, null, middleware.deny(['foo']), 403, 'text/html'),
      validate(false, null, middleware.deny(['read']), 403, 'text/html'),
      validate(false, 'bart', middleware.deny(['manage']), 403, 'text/html'),
      validate(false, 'burns', middleware.deny(['manage']), 403, 'text/html'),

      validate(false, 'homer', middleware.check(), 200, 'text/html')
    ]);
  });

  it('should ignore invalid permission values', function () {
    this.timeout(1000);

    return Promise.all([
      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.allow('create, update'), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.allow(['create', 'update']), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.allow([ ['create', 'foo'], 'update']), 200, 'text/html'),

      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.check(), 403, 'text/html')
    ]);
  });


  it('should fail if no user', function () {
    this.timeout(1000);

    return Promise.all([
      validate(MIDDLEWARE_OPTIONS, null, middleware.allow('create, update'), 403, 'text/html')
    ]);
  });


  it('should fail if no RBAC instance', function () {
    this.timeout(1000);

    return Promise.all([
      validate({}, 'homer', middleware.allow('create, update'), 403, 'text/html')
    ]);
  });


  it('should allow validating inside a custom middlewares', function () {
    this.timeout(1000);

    return Promise.all([
      validate(MIDDLEWARE_OPTIONS, 'phsycho bob', [
        function * (next) {
          var allowed = yield this.rbac.check('crc1');

          allowed.should.equal(1);

          yield* next;
        },
        function * (next) {
          var allowed = yield this.rbac.check('crc2');

          allowed.should.equal(2);

          yield* next;
        }
      ], 200, 'text/html')
    ]);
  });

});
