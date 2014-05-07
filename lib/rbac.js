
var InvalidProviderException = require('./exceptions').InvalidProviderException;
var InvalidRuleException = require('./exceptions').InvalidRuleException;


module.exports.middleware = middleware;
module.exports.allow = allow;
module.exports.deny = deny;

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

  ctxProperties = {
    _accessProvider: {
      enumerable: false,
      get: function getAccessProvider() { return provider; }
    },
    _allowedWeight: {
      enumerable: false,
      writable: true,
      value: null
    }
  };

  return function * rbac(next) {
    //this.userAccess = yield (provider.getUserRoles)(this);

    Object.defineProperties(this, ctxProperties);

    yield next;

    //this.userAccess = undefined;
  };
}


function * findMatchingRuleWeight(depth, roles, provider, permissions) {
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
    role = yield (provider.getRolePermissions)(roles[i]);

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
      inheritedWeight = yield findMatchingRuleWeight(depth + 1, role.inherited, provider, permissions);

      if (inheritedWeight !== false) {
        weight = inheritedWeight;
      }
    }

    //console.log("USER ROLE", depth, roles[i], permissions, role.permissions, weight);

  }

  return weight;
}



/**
Allow only the given permissions to continue down the pipe. If a string is
specified, each permission is separated by a space. If an array is specified,
each element is a defined permission to allow.

@param {String|Array} permissions  a list of permissions to allow
@param {String} redirectUrl        (optional) if not allowed, redirect to this url
@return {Function}                 the middleware function
*/
function allow(permissions, redirectUrl) {
  if (typeof permissions === 'string') {
    permissions = permissions.split(/\s+/);
  } else if (!Array.isArray(permissions)) {
    throw InvalidRuleException('Invalid permissions');
  }

  permissions = permissions.filter(function (item) { return (typeof item === 'string') && item.length; });

  if (!permissions.length) {
    throw InvalidRuleException('Invalid permissions');
  }

  return function * allowPermissions(next) {
    var userRoles;
    var i;
    var ilen;
    var roleDef;
    var ruleWeight;

    if (this._accessProvider) {
      userRoles = yield (this._accessProvider.getUserRoles)(this);

      ruleWeight = yield findMatchingRuleWeight(0, userRoles, this._accessProvider, permissions);

      //console.log("Rule weight", permissions, ruleWeight);
      if (ruleWeight === false) {
        if (this._allowedWeight === null) {
          if (redirectUrl) {
            //console.log("Not allowed", permissions, redirectUrl);
            this.redirect(redirectUrl);
          } else {
            this.status = 403;
            this.body = 'Forbidden';
          }
          return;
        }
      } else {
        if (this._allowedWeight === null) {
          this._allowedWeight = ruleWeight;
        } else {
          this._allowedWeight = Math.min(this._allowedWeight, ruleWeight);
        }
      }
    }

    yield next;
  };
}

/**
Deny only the given permissions to continue down the pipe. If a string is
specified, each permission is separated by a space. If an array is specified,
each element is a defined permission to deny.

@param {String|Array} permissions    a list of permissions to deny
@param {String} redirectUrl        (optional) if not allowed, redirect to this url
@return {Function}                   the middleware function
*/
function deny(permissions, redirectUrl) {
  if (typeof permissions === 'string') {
    permissions = permissions.split(/\s+/);
  } else if (!Array.isArray(permissions)) {
    throw InvalidRuleException('Invalid permissions');
  }

  permissions = permissions.filter(function (item) { return (typeof item === 'string') && item.length; });

  if (!permissions.length) {
    throw InvalidRuleException('Invalid permissions');
  }

  return function * denyPermissions(next) {
    var userRoles;
    var i;
    var ilen;
    var roleDef;
    var ruleWeight;

    if (this._accessProvider) {
      userRoles = yield (this._accessProvider.getUserRoles)(this);

      ruleWeight = yield findMatchingRuleWeight(0, userRoles, this._accessProvider, permissions);

      //console.log("DENY", this._allowedWeight, ruleWeight);
      if ((ruleWeight === false) ||
          ((this._allowedWeight !== null) && (this._allowedWeight < ruleWeight))) {

        return yield next;
      }
    }

    if (redirectUrl) {
      //console.log("Not allowed", permissions, redirectUrl);
      this.redirect(redirectUrl);
    } else {
      this.status = 403;
      this.body = 'Forbidden';
    }
  };
}
