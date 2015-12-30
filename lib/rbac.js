

const RBAC = require('rbac-a');

var InvalidProviderException = require('./exceptions').InvalidProviderException;
var InvalidRuleException = require('./exceptions').InvalidRuleException;

module.exports.middleware = module.exports = middleware;
module.exports.allow = allow;
module.exports.deny = deny;
module.exports.check = check;

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

  if (!('rbac' in options)) {
    options.rbac = new RBAC();
  } else if (!(options.rbac instanceof RBAC)) {
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
      value: Object.create(rbac, {
        // compat with 0.x
        allowedWeight: {
          enumerable: false,
          get: function () {
            return this.allowedPriority;
          }
        },
        // current allowed priority
        allowedPriority: {
          enumerable: false,
          writable: true,
          value: null
        },
        // current user's roles (optimize checking; assume roles don't change within request)
        rolesCache: {
          enumerable: false,
          writable: false,
          value: {}
        },
        isAllowed: {
          enumerable: true,
          writable: false,
          value: function (permissions) {
            return isAllowed(ctx, preparePermissionList(permissions));
          }
        },
        isDenied: {
          enumerable: true,
          writable: false,
          value: function (permissions) {
            return isDenied(ctx, preparePermissionList(permissions));
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



function * findMatchingRuleWeight(ctxRbac, depth, roles, permissions, permissionMatches, roleStack) {
  var i, ilen;
  var j, jlen;
  var k, klen;
  var role;
  var rolePermission;
  var inheritedRoles;
  var weight = false;

  roleStack = roleStack || [];
  permissionMatches = permissionMatches || {};

  if (!roles) {
    return false;
  }

  for (i = 0, ilen = roles.length; i < ilen; ++i) {
    roleStack.push(roles[i]);

    role = ctxRbac.rolesCache[roles[i]] || (yield* ctxRbac.accessProvider.getRolePermissions(roles[i]));

    if (role) {
      if (role.permissions) {
        for (j = 0, jlen = role.permissions.length; j < jlen; ++j) {
          rolePermission = role.permissions[j];

          if (!(rolePermission in permissionMatches)) {
            permissionMatches[rolePermission] = depth;
          }
        }

        if (permissions.some(function (p) {
          return p.every(function (pVal) {
            return pVal in permissionMatches;
          });
        })) {
          weight = depth;
        }
      }

      inheritedRoles = role.inherited && role.inherited.filter(function (r) {
        return roleStack.indexOf(r) === -1;
      });
    }

    if (weight === false && inheritedRoles && inheritedRoles.length) {
      weight = yield* findMatchingRuleWeight(ctxRbac, depth + 1, inheritedRoles, permissions, permissionMatches, roleStack);
    }

    roleStack.pop();
  }

  return weight;
}


/**
Returns true if the given context (ctx) is allowed with the provided permissions
*/
function * isAllowed(ctx, permissions, updateContext) {
  var userRoles;
  var ruleWeight = Infinity;
  var ctxRbac = ctx.rbac;

  if (ctxRbac && ctxRbac.accessProvider) {
    userRoles = yield* ctxRbac.accessProvider.getUserRoles(ctx);
    ruleWeight = yield* findMatchingRuleWeight(ctxRbac, 0, userRoles, permissions);

    if (ruleWeight === false) {
      if (ctxRbac.allowedWeight === null) {
        return false;
      } else {
        ruleWeight = Infinity;
      }
    } else if (updateContext) {
      if (ctxRbac.allowedWeight === null) {
        ctxRbac.allowedWeight = ruleWeight;
      } else {
        ctxRbac.allowedWeight = Math.min(ctxRbac.allowedWeight, ruleWeight);
      }
    }
  }


  return ruleWeight;
}

/**
Returns true if the given context (ctx) is allowed with the provided permissions
*/
function * isDenied(ctx, permissions) {
  var userRoles;
  var ruleWeight = Infinity;
  var ctxRbac = ctx.rbac;

  if (ctxRbac && ctxRbac.accessProvider) {
    userRoles = yield* ctxRbac.accessProvider.getUserRoles(ctx);
    ruleWeight = yield* findMatchingRuleWeight(ctxRbac, 0, userRoles, permissions);

    // DO NOT deny if the user do not own the role, or if the role's weight is greater than the allowed weight
    if ((ruleWeight === false) || ((ctxRbac.allowedWeight !== null) && (ctxRbac.allowedWeight < ruleWeight))) {
      return false;
    }
  }


  return ruleWeight;
}




/**
Allow only the given permissions to continue down the pipe. If a string is
specified, each permission is separated by a comma. If an array is specified,
each element is a defined permission to allow.

@param {String|Array} permissions  a list of permissions to allow
@param {String} redirectUrl        (optional) if not allowed, redirect to this url
@return {Function}                 the middleware function
*/
function allow(permissions, redirectUrl) {
  permissions = preparePermissionList(permissions);

  return function * allowPermissions(next) {
    var allowedWeight = yield* isAllowed(this, permissions, true);

    if (allowedWeight !== false) {
      return yield next;
    } else {
      if (redirectUrl && !this.accepts('json')) {
        this.redirect(redirectUrl);
      } else {
        this.status = 403;
        this.body = 'Forbidden';
      }
    }
  };
}

/**
Deny only the given permissions to continue down the pipe. If a string is
specified, each permission is separated by a comma. If an array is specified,
each element is a defined permission to deny.

@param {String|Array} permissions    a list of permissions to deny
@param {String} redirectUrl        (optional) if not allowed, redirect to this url
@return {Function}                   the middleware function
*/
function deny(permissions, redirectUrl) {
  permissions = preparePermissionList(permissions);

  return function * denyPermissions(next) {
    var deniedWeight = yield* isDenied(this, permissions);
    var allowedWeight = this.rbac && this.rbac.allowedWeight || null;

    if (deniedWeight !== false && (allowedWeight === null || (deniedWeight <= allowedWeight))) {
      if (redirectUrl && !this.accepts('json')) {
        this.redirect(redirectUrl);
      } else {
        this.status = 403;
        this.body = 'Forbidden';
      }
    } else {
      return yield next;
    }
  };
}



function check(permissions, redirectUrl) {
  var allowPermissions;
  var denyPermissions;

  if (permissions['allow']) {
    allowPermissions = preparePermissionList(permissions['allow']);
  }
  if (permissions['deny']) {
    denyPermissions = preparePermissionList(permissions['deny']);
  }

  if (!allowPermissions && !denyPermissions) {
    throw InvalidRuleException('Missing permissions');
  }

  return function * checkPermissions(next) {
    var allowedWeight = allowPermissions ? yield* isAllowed(this, allowPermissions, true) : Infinity;
    var deniedWeight = denyPermissions ? yield* isDenied(this, denyPermissions) : false;

    if ( (allowedWeight !== false) &&
         ((deniedWeight === false) || (allowedWeight < deniedWeight)) ) {

      return yield next;
    } else {
      if (redirectUrl && !this.accepts('json')) {
        this.redirect(redirectUrl);
      } else {
        this.status = 403;
        this.body = 'Forbidden';
      }
    }
  };
}