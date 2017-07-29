
const RBAC = require('rbac-a');

/**
Define custom error type
*/
class InvalidOptionException extends Error {}

/**
 Koa middleware.

 Options
 - rbac {RBAC}         (optional) the RBAC-A instance (will create one if omitted)
 - identify {Function} (optional) the identity function. By default, a function returning ctx.user will be used.

 @param options {Object}
 @return {Function}                the middleware function
 */
function middleware (options) {
  options = options || {};

  if (('rbac' in options) && !(options.rbac instanceof RBAC)) {
    throw new InvalidOptionException('Invalid RBAC instance');
  }

  if (!('identity' in options)) {
    options.identity = defaultIdentity;
  } else if (typeof options.identity !== 'function') {
    throw new InvalidOptionException('Invalid identity function');
  }

  if (('restrictionHandler' in options) && (typeof options.restrictionHandler !== 'function')) {
    throw new InvalidOptionException('Invalid restriction handler');
  }

  return (ctx, next) => {
    Object.defineProperty(ctx, 'rbac', {
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
          value: function restrict(permissions, redirectUrl) {
            if (options.restrictionHandler) {
              return options.restrictionHandler(ctx, permissions, redirectUrl);
            } else if (redirectUrl) {
              return ctx.redirect(redirectUrl);
            } else {
              ctx.status = 403;
              ctx.body = 'Forbidden';
            }
          }
        }
      })
    });

    return next();
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

  return async (ctx, next) => {
    const rbac = ctx.rbac;

    if (rbac) {
      const allowedPriority = await rbac.check(permissions, params);

      if (!allowedPriority) {
        return rbac._restrict(permissions, redirectUrl);
      }
    }

    return next();
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

  return async (ctx, next) => {
    const rbac = ctx.rbac;

    if (rbac) {
      const deniedPriority = await rbac.check(permissions, params);

      if (deniedPriority) {
        return rbac._restrict(permissions, redirectUrl);
      }
    } else {
      ctx.status = 403;
      ctx.body = 'Forbidden';
      return;
    }

    return next();
  };
}


/**
 Return a middleware to allow and not deny any with the given permissions.

 @param permissions {object} (optional)                      permissions sent to the RBAC-A instance
 @param permissions.allowPermissions {string|Array<string>}  the required permissions
 @param permissions.deniedPermissions {string|Array<string>} the restricted permissions
 @param params {object} (optional)                           params sent to the RBAC-A instance
 @param redirectUrl {string} (optional)                      if not allowed, try to redirect
 */
function checkMiddleware(permissions, params, redirectUrl) {
  if (arguments.length < 3 && typeof params === 'string') {
    redirectUrl = params;
    params = undefined;
  }

  return async (ctx, next) => {
    const rbac = ctx.rbac;

    if (rbac) {
      let allowedPriority;
      let deniedPriority;

      permissions = permissions || {};

      if ('allow' in permissions) {
        allowedPriority = await rbac.check(permissions['allow'], params);
      } else {
        allowedPriority = Infinity;
      }

      if ('deny' in permissions) {
        deniedPriority = await rbac.check(permissions['deny'], params);
      } else {
        deniedPriority = Infinity;
      }

      if (isNaN(allowedPriority) || (!isNaN(deniedPriority) && (deniedPriority <= allowedPriority))) {
        return rbac._restrict(permissions, redirectUrl);
      }
    }

    return next();
  };
}


module.exports = middleware;
module.exports.middleware = middleware;
module.exports.allow = allowMiddleware;
module.exports.deny = denyMiddleware;
module.exports.check = checkMiddleware;
module.exports.InvalidOptionException = InvalidOptionException;
module.exports.RBAC = RBAC;
