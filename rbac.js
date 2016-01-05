
const RBAC = require('rbac-a');
const errorFactory = require('error-factory');

const InvalidOptionException = errorFactory('rbac.InvalidOptionException');


module.exports = middleware;
module.exports.middleware = middleware;
module.exports.allow = allowMiddleware;
module.exports.deny = denyMiddleware;
module.exports.check = checkMiddleware;
module.exports.InvalidOptionException = InvalidOptionException;
module.exports.RBAC = RBAC;


/**
Koa middleware.

Options
 - rbac {RBAC}         (optional) the RBAC-A instance (will create one if omitted)
 - identify {Function} (optional) the identity function. By default, a function returning ctx.user will be used.

@param options {Object}
@return {Function}                the middleware function
*/
function middleware(options) {
  options = options || {};

  if (('rbac' in options) && !(options.rbac instanceof RBAC)) {
    throw InvalidOptionException('Invalid RBAC instance');
  }

  if (!('identity' in options)) {
    options.identity = defaultIdentity;
  } else if (typeof options.identity !== 'function') {
    throw InvalidOptionException('Invalid identity function');
  }

  return function * (next) {
    const ctx = this;   // koa 1.x style

    Object.defineProperty(this, 'rbac', {
      enumerable: true,
      writable: false,
      value: Object.create(options.rbac || {}, {
        // current allowed priority
        check: {
          enumerable: true,
          writable: false,
          value: function (permissions, params) {
            return options.rbac && Promise.resolve().then(function () {
              return options.identity(ctx);
            }).then(function (user) {
              return user && options.rbac.check(user, permissions, params) || NaN;
            }) || Promise.resolve(NaN);
          }
        },
        _restrict: {
          enumerable: false,
          writable: false,
          value: function restrict(redirectUrl) {
            // TODO : conditional redirect

            if (redirectUrl) {
              return ctx.redirect(redirectUrl);
            } else {
              ctx.status = 403;
              ctx.body = 'Forbidden';
            }
          }
        }
      })
    });

    yield next;
  };
}


/**
Default identity function.

Try to return most common used user property.

@param ctx    the request context
@return mixed
*/
function defaultIdentity(ctx) {
  return ctx && ctx.user;
}


/**
Return a middleware to allow only for the given permissions.

@param permissions {string}            the required permissions
@param params {object} (optional)      params sent to the RBAC-A instance
@param redirectUrl {string} (optional) if not allowed, try to redirect
*/
function allowMiddleware(permissions, params, redirectUrl) {
  if (arguments.length < 3 && typeof params === 'string') {
    redirectUrl = params;
    params = undefined;
  }

  return function * (next) {
    const rbac = this.rbac;
    var allowedPriority;

    if (rbac) {
      allowedPriority = yield rbac.check(permissions, params);

      if (!allowedPriority) {
        return rbac._restrict(redirectUrl);
      }
    }

    yield next;
  };
}


/**
Return a middleware to deny any with the given permissions.

@param permissions {string}            the restricted permissions
@param params {object} (optional)      params sent to the RBAC-A instance
@param redirectUrl {string} (optional) if not allowed, try to redirect
*/
function denyMiddleware(permissions, params, redirectUrl) {
  if (arguments.length < 3 && typeof params === 'string') {
    redirectUrl = params;
    params = undefined;
  }

  return function * (next) {
    const rbac = this.rbac;
    var deniedPriority;

    if (rbac) {
      deniedPriority = yield rbac.check(permissions, params);

      if (deniedPriority) {
        return rbac._restrict(redirectUrl);
      }
    } else {
      this.status = 403;
      this.body = 'Forbidden';
      return;
    }

    yield next;
  };
}


/**
Return a middleware to allow and not deny any with the given permissions.

@param allowPermissions {string}       the required permissions
@param deniedPermissions {string}      the restricted permissions
@param params {object} (optional)      params sent to the RBAC-A instance
@param redirectUrl {string} (optional) if not allowed, try to redirect
*/
function checkMiddleware(permissions, params, redirectUrl) {
  if (arguments.length < 3 && typeof params === 'string') {
    redirectUrl = params;
    params = undefined;
  }

  return function * (next) {
    const rbac = this.rbac;
    var allowedPriority;
    var deniedPriority;

    if (rbac) {
      permissions = permissions || {};

      if ('allow' in permissions) {
        allowedPriority = yield rbac.check(permissions['allow'], params);
      } else {
        allowedPriority = Infinity;
      }

      if ('deny' in permissions) {
        deniedPriority = yield rbac.check(permissions['deny'], params);
      } else {
        deniedPriority = Infinity;
      }

      if (isNaN(allowedPriority) || (!isNaN(deniedPriority) && (deniedPriority <= allowedPriority))) {
        return rbac._restrict(redirectUrl);
      }
    }

    yield next;
  };
}




