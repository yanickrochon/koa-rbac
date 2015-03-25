
const PERMISSION_SEP_OR = ',';
const PERMISSION_SEP_AND = '&&';

var InvalidProviderException = require('./exceptions').InvalidProviderException;
var InvalidRuleException = require('./exceptions').InvalidRuleException;


module.exports.middleware = middleware;
module.exports.allow = allow;
module.exports.deny = deny;
module.exports.check = check;

/**
Koa middleware.

@param {Object} provider   an object offering two methods : getRolePermissions and getUserRoles
@return {Function}         the middleware function
*/
function middleware(provider) {
  var ctxProperty;

  if (!provider || typeof provider !== 'object') {
    throw InvalidProviderException('Invalid provider');
  } else if (!(provider.getRolePermissions instanceof Function)) {
    throw InvalidProviderException('Missing function `getRolePermissions` in provider');
  } else if (!(provider.getUserRoles instanceof Function)) {
    throw InvalidProviderException('Missing function `getUserRoles` in provider');
  }

  ctxProperty = Object.create(null, {
    accessProvider: {
      enumerable: true,
      get: function getAccessProvider() { return provider; }
    }
  });

  return function * rbac(next) {
    var ctx = this;

    Object.defineProperty(this, 'rbac', {
      enumerable: true,
      writable: false,
      value: Object.create(ctxProperty, {
        allowedWeight: {
          enumerable: false,
          writable: true,
          value: null
        },
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
Prepare the given permissions list to be used for validation

@param {String|Array} permissions  a list of permissions to allow
*/
function preparePermissionList(permissions) {
  if (typeof permissions === 'string') {
    permissions = permissions.split(PERMISSION_SEP_OR);
  } else if (!Array.isArray(permissions)) {
    throw InvalidRuleException('Invalid permissions');
  }

  permissions = permissions.filter(function (perm) {
    return (typeof perm === 'string' || Array.isArray(perm)) && perm.length;
  }).map(function (perm) {
    perm = Array.isArray(perm) ? perm : perm.split(PERMISSION_SEP_AND);
    return perm.filter(function (p) {
        return (typeof p === 'string') && p.length;
      }).map(function (p) {
        return p.trim();
      })
    ;
  });

  if (!permissions.length) {
    throw InvalidRuleException('Invalid permissions');
  }

  return permissions;
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