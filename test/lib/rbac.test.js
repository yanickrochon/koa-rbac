

describe('Test RBAC', function () {

  var request = require('supertest');
  var koa = require('koa');
  var rbac = require('../../lib/rbac');

  var roles = {
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
    }
  };

  var userRoles = {
    'bart': ['guest', 'reader'],
    'marge': ['editor'],
    'homer': ['admin', 'director'],
    'burns': ['admin']
  };

  var accessProvider = new function AccessProvider() {
    this.getRolePermissions = getRolePermissions;
    this.getUserRoles = getUserRoles;
  }

  /**
  Return the role defined by `roleName`
  */
  function * getRolePermissions(roleName) {
    // NOTE : the method should return an object similar to the one described here
    return roles[roleName];
  }

  /**
  Return the roles assigned to the user. Each item of the returned array will
  invoke `getRole` with it's item value
  */
  function * getUserRoles(ctx) {
    return userRoles[ctx.identity];
  }


  it('should be a valid provider', function () {
    [
      undefined, null, false, true, 0, '', [], {},
      function () {}, function * () {},
      { getRolePermissions: function () {} }
    ].forEach(function (invalidProvider) {
      +function () { rbac.middleware(invalidProvider); }.should.throw();
    });
  });

  it('should be valid permissions', function () {
    [
      undefined, null, false, true, 0, '', [], {},
    ].forEach(function (invalidPermissions) {
      +function () { rbac.allow(invalidPermissions); }.should.throw();
      +function () { rbac.deny(invalidPermissions); }.should.throw();
    });
  });

  it('should allow / deny', function * () {
    this.timeout(1000);

    function validate(identity, validateionMiddleware, status) {
      var app = koa();

      app.use(function * (next) {
        this.identity = identity;

        yield next;
      });

      app.use(rbac.middleware(accessProvider));
      app.use(validateionMiddleware);

      app.use(function * () {
        this._accessProvider.should.equal(accessProvider);
        this.status = 200;
      });

      return function (done) {
        request(app.listen())
        .get('/')
        .expect(status, done);
      };
    }

    yield validate('bart', rbac.allow(['read']), 200);
    yield validate('marge', rbac.allow(['update']), 200);

    yield validate('homer', rbac.allow(['create', 'update']), 200);
    yield validate('homer', rbac.allow('create, update'), 200);

    yield validate('burns', rbac.allow(['manage']), 200);

    yield validate('homer', rbac.allow(['foo']), 200);

    yield validate('burns', rbac.allow(['read']), 403);

    yield validate('bart', rbac.deny(['read']), 403);
    yield validate('burns', rbac.deny(['read', 'update']), 200);
    yield validate('burns', rbac.deny(['read', 'manage']), 403);

    yield validate('bart', rbac.check({
      'allow': 'read'
    }), 200);
    yield validate('burns', rbac.check({
      'deny': ['read', 'update']
    }), 200);
    yield validate('burns', rbac.check({
      'deny': ['read', 'manage']
    }), 403);

    // redirect
    yield validate('bart', rbac.allow('read', '/foo'), 200);
    yield validate('marge', rbac.allow(['update'], '/foo'), 200);
    yield validate('bart', rbac.deny(['read'], '/foo'), 302);

    yield validate('burns', rbac.deny(['read', 'update'], '/foo'), 200);
    yield validate('bart', rbac.deny(['read'], '/foo'), 302);
    yield validate('burns', rbac.deny(['read', 'manage'], '/foo'), 302);

    yield validate('marge', rbac.check({
      'allow': ['update'],
      'deny': ['read']
    }), 200);
    yield validate('marge', rbac.check({
      'allow': ['manage'],
      'deny': ['read']
    }), 403);
    yield validate('marge', rbac.check({
      'allow': ['manage'],
      'deny': ['read']
    }, '/foo'), 302);

  });


  it('should allow / deny if no middleware', function * () {
    this.timeout(1000);

    function validate(identity, validateionMiddleware, status) {
      var app = koa();

      app.use(function * (next) {
        if (identity) {
          this.identity = identity;
        }
        yield next;
      });

      app.use(validateionMiddleware);

      app.use(function * () {
        assert.equal(this._accessProvider, undefined);
        this.status = 200;
      });

      return function (done) {
        request(app.listen())
        .get('/')
        .expect(status, done);
      };
    }

    yield validate(null, rbac.allow('read'), 200);
    yield validate('bart', rbac.allow(['manage']), 200);
    yield validate('burns', rbac.allow(['read']), 200);

    yield validate(null, rbac.deny(['foo']), 403);
    yield validate(null, rbac.deny(['read']), 403);
    yield validate('bart', rbac.deny(['manage']), 403);
    yield validate('burns', rbac.deny(['manage']), 403);

  });


  it('should allow composed rules', function * () {
    this.timeout(1000);

    function validate(identity, validateionMiddlewares, status) {
      var app = koa();

      app.use(function * (next) {
        this.identity = identity;

        yield next;
      });

      app.use(rbac.middleware(accessProvider));
      validateionMiddlewares.forEach(function (validateionMiddleware) {
        app.use(validateionMiddleware);
      });

      app.use(function * () {
        this._accessProvider.should.equal(accessProvider);
        this.status = 200;
      });

      return function (done) {
        request(app.listen())
        .get('/')
        .expect(status, done);
      };
    }

    yield validate('marge', [ rbac.allow('read, update'), rbac.deny('read') ], 200);
    yield validate('marge', [ rbac.allow('read'), rbac.deny('read') ], 403);
    yield validate('marge', [ rbac.allow('read'), rbac.allow('update'), rbac.deny('read') ], 200);
    yield validate('marge', [ rbac.allow('update'), rbac.allow('read'), rbac.deny('read') ], 200);
    yield validate('marge', [ rbac.allow('update'), rbac.allow('manage'), rbac.deny('read') ], 200);

    yield validate('marge', [ rbac.check({
      'allow': [ 'update', 'manage' ],
      'deny': 'read'
    }) ], 200);
    yield validate('marge', [ rbac.check({
      'allow': [ 'read' ]
    }), rbac.deny('read') ], 403);

  });

});
