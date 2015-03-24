

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
    },

    'cyclic1': {
      permissions: ['crc1'],
      inherited: ['cyclic2']
    },
    'cyclic2': {
      permissions: ['crc2'],
      inherited: ['cyclic1']
    }
  };

  var userRoles = {
    'bart': ['guest', 'reader'],
    'marge': ['editor'],
    'homer': ['admin', 'director'],
    'burns': ['admin'],
    'phsycho bob': ['cyclic1']
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


  function validate(useRbacMiddleware, identity, validateionMiddleware, status, accept) {
    var app = koa();

    app.use(function * (next) {
      if (identity) {
        this.identity = identity;
      }
      yield next;
    });

    if (useRbacMiddleware) {
      app.use(rbac.middleware(accessProvider));
    }
    if (Array.isArray(validateionMiddleware)) {
      validateionMiddleware.forEach(function (middleware) {
        app.use(middleware);
      });
    } else {
      app.use(validateionMiddleware);
    }

    app.use(function * () {
      assert.equal(this._accessProvider, undefined);
      //this.rbac.accessProvider.should.equal(accessProvider);
      this.status = 200;
    });

    return function (done) {
      request(app.listen())
      .get('/')
      .set('Accept', accept)
      .expect(status, done);
    };
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

    yield validate(true, 'bart', rbac.allow(['read']), 200, 'text/html');
    yield validate(true, 'marge', rbac.allow(['update']), 200, 'text/html');


    yield validate(true, 'homer', rbac.allow(['create', 'update']), 200, 'text/html');
    yield validate(true, 'homer', rbac.allow('create, update'), 200, 'text/html');

    yield validate(true, 'burns', rbac.allow(['manage']), 200, 'text/html');

    yield validate(true, 'homer', rbac.allow(['foo']), 200, 'text/html');

    yield validate(true, 'burns', rbac.allow(['read']), 403, 'text/html');

    yield validate(true, 'bart', rbac.deny(['read']), 403, 'text/html');
    yield validate(true, 'burns', rbac.deny(['read', 'update']), 200, 'text/html');
    yield validate(true, 'burns', rbac.deny(['read', 'manage']), 403, 'text/html');

    yield validate(true, 'bart', rbac.check({
      'allow': 'read'
    }), 200, 'text/html');
    yield validate(true, 'burns', rbac.check({
      'deny': ['read', 'update']
    }), 200, 'text/html');
    yield validate(true, 'burns', rbac.check({
      'deny': ['read', 'manage']
    }), 403, 'text/html');

    // redirect
    yield validate(true, 'bart', rbac.allow('read', '/foo'), 200, 'text/html');
    yield validate(true, 'marge', rbac.allow(['update'], '/foo'), 200, 'text/html');
    yield validate(true, 'bart', rbac.deny(['read'], '/foo'), 302, 'text/html');
    yield validate(true, 'bart', rbac.deny(['read'], '/foo'), 403, 'application/json');

    yield validate(true, 'burns', rbac.deny(['read', 'update'], '/foo'), 200, 'text/html');
    yield validate(true, 'bart', rbac.deny(['read'], '/foo'), 302, 'text/html');
    yield validate(true, 'bart', rbac.deny(['read'], '/foo'), 403, 'application/json');
    yield validate(true, 'burns', rbac.deny(['read', 'manage'], '/foo'), 302, 'text/html');
    yield validate(true, 'burns', rbac.deny(['read', 'manage'], '/foo'), 403, 'application/json');

    yield validate(true, 'marge', rbac.check({
      'allow': ['update'],
      'deny': ['read']
    }), 200, 'text/html');
    yield validate(true, 'marge', rbac.check({
      'allow': ['manage'],
      'deny': ['read']
    }), 403, 'text/html');
    yield validate(true, 'marge', rbac.check({
      'allow': ['manage'],
      'deny': ['read']
    }, '/foo'), 302, 'text/html');
    yield validate(true, 'marge', rbac.check({
      'allow': ['manage'],
      'deny': ['read']
    }, '/foo'), 403, 'application/json ');

  });


  it('should allow / deny if no middleware', function * () {
    this.timeout(1000);

    yield validate(false, null, rbac.allow('read'), 200, 'text/html');
    yield validate(false, 'bart', rbac.allow(['manage']), 200, 'text/html');
    yield validate(false, 'burns', rbac.allow(['read']), 200, 'text/html');

    yield validate(false, null, rbac.deny(['foo']), 403, 'text/html');
    yield validate(false, null, rbac.deny(['read']), 403, 'text/html');
    yield validate(false, 'bart', rbac.deny(['manage']), 403, 'text/html');
    yield validate(false, 'burns', rbac.deny(['manage']), 403, 'text/html');

  });


  it('should allow composed rules', function * () {
    this.timeout(1000);

    yield validate(true, 'marge', [ rbac.allow('read, update'), rbac.deny('read') ], 200, 'text/html');
    yield validate(true, 'marge', [ rbac.allow('read'), rbac.deny('read') ], 403, 'text/html');
    yield validate(true, 'marge', [ rbac.allow('read'), rbac.allow('update'), rbac.deny('read') ], 200, 'text/html');
    yield validate(true, 'marge', [ rbac.allow('update'), rbac.allow('read'), rbac.deny('read') ], 200, 'text/html');
    yield validate(true, 'marge', [ rbac.allow('update'), rbac.allow('manage'), rbac.deny('read') ], 200, 'text/html');

    yield validate(true, 'marge', [ rbac.check({
      'allow': [ 'update', 'manage' ],
      'deny': 'read'
    }) ], 200, 'text/html');
    yield validate(true, 'marge', [ rbac.check({
      'allow': [ 'read' ]
    }), rbac.deny('read') ], 403, 'text/html');

  });


  it('should allow ALL rules', function * () {
    this.timeout(1000);

    yield validate(true, 'marge', rbac.allow('read && update'), 200, 'text/html');
  });


  it('should detect and handle cyclical dependencies', function * () {
    yield validate(true, 'phsycho bob', rbac.allow('crc1'), 200, 'text/html');
    //yield validate(true, 'phsycho bob', rbac.allow('crc2'), 200, 'text/html');
  });

});
