
describe('Test RBAC', () => {

  const assert = require('assert');
  const request = require('supertest');
  const koa = require('koa');
  const RBAC = require('rbac-a');
  const JsonProvider = require('rbac-a/lib/providers/json');

  const middleware = require('../koa-rbac');

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
    rbac: new RBAC({ provider: new JsonProvider(RULES) })
  };


  function validate(useRbacMiddleware, identity, validateionMiddleware, status, accept) {
    const app = new koa();

    if (identity) {
      app.use((ctx, next) => {
        ctx.user = identity;
        return next();
      });
    }

    if (useRbacMiddleware) {
      app.use(middleware(useRbacMiddleware));
    }
    if (Array.isArray(validateionMiddleware)) {
      validateionMiddleware.forEach(middleware => app.use(middleware));
    } else {
      app.use(validateionMiddleware);
    }

    app.use(function (ctx) {
      ctx.status = 200;
    });

    const error = new Error();

    return request(app.listen())
      .get('/')
      .set('Accept', accept)
      .expect(status)
      .catch(err => {
        error.message = err.message;
        throw error;
      })
    ;
  }


  it('should return middleware with default options', () => {
    assert.ok(middleware() instanceof Function, 'Middleware is not a function');
  });

  it('should be a valid RBAC-A instance', () => {
    [
      undefined, null, false, true, 0, NaN, Infinity, '', 'hello', [], {},
      function () {}, async function () {}, function RBAC() {},
      /./, new Date()
    ].forEach(rbac => assert.throws(() => middleware({ rbac }), 'Did not throw with value : ' + JSON.stringify(rbac)));
  });

  it('should be a valid identity function', () => {
    [
      undefined, null, false, true, 0, NaN, Infinity, '', 'hello', [], {},
      /./, new Date()
    ].forEach(identity => assert.throws(() => middleware({ identity }), 'Did not throw with value : ' + JSON.stringify(identity)));
  });

  it('should be a valid restriction handler', () => {
    [
      undefined, null, false, true, 0, NaN, Infinity, '', 'hello', [], {},
      /./, new Date()
    ].forEach(restrictionHandler => assert.throws(() => middleware({ restrictionHandler }), 'Did not throw with value : ' + JSON.stringify(restrictionHandler)));
  });

  it('should accept valid RBAC-A instance', () => {
    const rbac = new RBAC({ provider: new JsonProvider(RULES) });
    const options = {
      rbac: rbac
    };

    middleware(options);

    assert.strictEqual(options.rbac, rbac, 'Failed to set rbac instance');
  });

  it('should accept valid identity function', () => {
    const identity = function () {};
    const options = {
      identity: identity
    };

    middleware(options);

    assert.strictEqual(options.identity, identity, 'Failed to set identity function');
  });

  it('should allow / deny', () => {
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
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.allow('read', '/foo'), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.allow(['update'], {}, '/foo'), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.allow('manage','/foo'), 302, 'text/html'),

      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read'], {}, '/foo'), 302, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read'], '/foo'), 302, 'application/json'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.deny(['read', 'update'], null, '/foo'), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read'], '/foo'), 302, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'bart', middleware.deny(['read'], null, '/foo'), 302, 'application/json'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.deny(['read', 'manage'], null, '/foo'), 302, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'burns', middleware.deny(['read', 'manage'], null, '/foo'), 302, 'application/json'),

      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.check({ 'allow': ['manage'], 'deny': ['read'] }, '/foo'), 302, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'marge', middleware.check({ 'allow': ['manage'], 'deny': ['read'] }, {}, '/foo'), 302, 'application/json '),
    ]);
  });


  it('should allow / deny if no middleware', () => {
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

  it('should execute restriction handler on deny', () => {
    const middlewareOptions = {
      rbac: new RBAC({ provider: new JsonProvider(RULES) }),
      restrictionHandler: (ctx, permissions) => {
        restricted.push(permissions);
        ctx.status = 418;
      }
    }
    var restricted = [];

    return Promise.all([
      validate(middlewareOptions, 'bart', middleware.allow(['read']), 200, 'text/html'),
      validate(middlewareOptions, 'bart', middleware.deny(['read'], '/foo'), 418, 'application/json'),
      validate(middlewareOptions, 'burns', middleware.deny(['read', 'manage'], null, '/foo'), 418, 'application/json'),
    ]).then(() => {
      const expected = [
        ["read"],
        ["read","manage"]
      ];
      assert.deepStrictEqual(restricted, expected, 'Failed to received expected restriction : ' + JSON.stringify(restricted));
    });
  });

  it('should ignore invalid permission values', () => {
    return Promise.all([
      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.allow('create, update'), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.allow(['create', 'update']), 200, 'text/html'),
      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.allow([ ['create', 'foo'], 'update']), 200, 'text/html'),

      validate(MIDDLEWARE_OPTIONS, 'homer', middleware.check(), 403, 'text/html')
    ]);
  });


  it('should fail if no user', () => {
    return Promise.all([
      validate(MIDDLEWARE_OPTIONS, null, middleware.allow('create, update'), 403, 'text/html')
    ]);
  });


  it('should fail if no RBAC instance', () => {
    return Promise.all([
      validate({}, 'homer', middleware.allow('create, update'), 403, 'text/html')
    ]);
  });


  it('should allow validating inside a custom middlewares', () => {
    return Promise.all([
      validate(MIDDLEWARE_OPTIONS, 'phsycho bob', [
        async (ctx, next) => {
          const allowed = await ctx.rbac.check('crc1');

          assert.strictEqual(allowed, 1, 'Failed to check crc1');

          return next();
        },
        async (ctx, next) => {
          const allowed = await ctx.rbac.check('crc2');

          assert.strictEqual(allowed, 2, 'Failed to check crc2');

          return next();
        }
      ], 200, 'text/html')
    ]);
  });

});
