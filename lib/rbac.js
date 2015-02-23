
const PERMISSION_SEP = ',';

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
          enumerable: true,
          writable: true,
          value: null
        },
        rolesCache: {
          enumerable: true,
          writable: false,
          value: {}
        },
        isAllowed: {
          enumerable: true,
          writable: false,
          value: function (permissions) {
            return isAllowed(ctx, permissions);
          }
        },
        isDenied: {
          enumerable: true,
          writable: false,
          value: function (permissions) {
            return isDenied(ctx, permissions);
          }
        }
      })
    });

    yield next;
  };
}


function * findMatchingRuleWeight(ctxRbac, depth, roles, permissions) {
  var i;
  var ilen;
  var j;
  var jlen;
  //var k;
  //var klen;
  var role;
  var weight = false;
  var inheritedWeight;

  //console.log(roles, permissions);

  for (i = 0, ilen = roles.length; i < ilen; ++i) {
    role = ctxRbac.rolesCache[roles[i]] || (yield ctxRbac.accessProvider.getRolePermissions(roles[i]));

    if (role.permissions) {
      for (j = 0, jlen = role.permissions.length; j < jlen; ++j) {
        //for (k = 0, klen = permissions.length; k < klen; ++k) {
          //if (permissions[k] === role.permissions[j]) {
        if (permissions.indexOf(role.permissions[j]) >= 0) {
          if ((weight === false) || (weight > depth)) {
            weight = depth;
          }
        }
      }
    }

    //console.log("Check inheritence", roles[i], role.inherited);
    if (weight === false && role.inherited) {
      inheritedWeight = yield findMatchingRuleWeight(ctxRbac, depth + 1, role.inherited, permissions);

      if (inheritedWeight !== false) {
        weight = inheritedWeight;
      }
    }

    //console.log("USER ROLE", depth, roles[i], permissions, role.permissions, weight);

  }

  return weight;
}


/**
Returns true if the given context (ctx) is allowed with the provided permissions
*/
function * isAllowed(ctx, permissions, updateContext) {
  var userRoles;
  var ruleWeight;
  var ctxRbac = ctx.rbac;

  if (ctxRbac && ctxRbac.accessProvider) {
    userRoles = yield ctxRbac.accessProvider.getUserRoles(ctx);
    ruleWeight = yield findMatchingRuleWeight(ctxRbac, 0, userRoles, permissions);

    //console.log("Rule weight", permissions, ruleWeight);
    if (ruleWeight === false) {
      if (ctxRbac.allowedWeight === null) {
        return false;
      }
    } else if (updateContext) {
      if (ctxRbac.allowedWeight === null) {
        ctxRbac.allowedWeight = ruleWeight;
      } else {
        ctxRbac.allowedWeight = Math.min(ctxRbac.allowedWeight, ruleWeight);
      }
    }
  }

  return true;
}

/**
Returns true if the given context (ctx) is allowed with the provided permissions
*/
function * isDenied(ctx, permissions) {
  var userRoles;
  var ruleWeight;
  var ctxRbac = ctx.rbac;

  if (ctxRbac && ctxRbac.accessProvider) {
    userRoles = yield ctxRbac.accessProvider.getUserRoles(ctx);
    ruleWeight = yield findMatchingRuleWeight(ctxRbac, 0, userRoles, permissions);

    //console.log("DENY", ctxRbac.allowedWeight, ruleWeight);
    if ((ruleWeight === false) ||
        ((ctxRbac.allowedWeight !== null) && (ctxRbac.allowedWeight < ruleWeight))) {

      return false;
    }
  }

  return true;
}


/**
Prepare the given permissions list to be used for validation

@param {String|Array} permissions  a list of permissions to allow
*/
function preparePermissionList(permissions) {
  if (typeof permissions === 'string') {
    permissions = permissions.split(PERMISSION_SEP);
  } else if (!Array.isArray(permissions)) {
    throw InvalidRuleException('Invalid permissions');
  }

  permissions = permissions.filter(function (perm) {
    return (typeof perm === 'string') && perm.length;
  }).map(function (perm) {
    return perm.trim();
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
    if (yield isAllowed(this, permissions, true)) {
      return yield next;
    } else {
      if (redirectUrl) {
        //console.log("Not allowed", permissions, redirectUrl);
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
    if (yield isDenied(this, permissions)) {
      if (redirectUrl) {
        //console.log("Not allowed", permissions, redirectUrl);
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

  if (permissions === null || typeof permissions !== 'object') {
    throw InvalidRuleException('Invalid permissions');
  }

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
    if ((!allowPermissions || (yield isAllowed(this, allowPermissions, true))) &&
        !(denyPermissions && (yield isDenied(this, denyPermissions))) ) {

      return yield next;
    } else {
      if (redirectUrl) {
        //console.log("Not allowed", permissions, redirectUrl);
        this.redirect(redirectUrl);
      } else {
        this.status = 403;
        this.body = 'Forbidden';
      }
    }
  };
}