
var MissingOptionException = require('./exceptions').MissingOptionException;


module.exports.middleware = middleware;
module.exports.allow = allow;
module.exports.deny = deny;

/**
Koa middleware.

Options:

 - {Function} loadUserAccess   a function with the request as context (this) and
                               should return an object describing the user access.
*/
function middleware(options) {
  options = options || {};

  if (!(options.loadUserAccess instanceof Function)) {
    throw MissingOptionException('Missing function `loadUserAccess`');
  }

  return function * rbac(next) {
    this.userAccess = yield (options.loadUserAccess.call)(this);

    yield next;

    //this.userAccess = undefined;
  };
}


/**
Allow only the given action to continue down the pipe. If a string is
specified, each action is separated by a space. If an array is specified, each
element is a defined action to allow.

@param {String|Array} actions     a list of actions to allow
@return {Function}                the middleware function
*/
function allow(actions) {
  if (typeof actions === 'string') {
    actions = actions.split(/\s+/);
  }

  return function * allowActions(next) {
    var restrictedActions;

    if (actions instanceof Function) {
      restrictedActions = yield actions.call(this);

      if (typeof restrictedActions === 'string') {
        restrictedActions = restrictedActions.split(/\s+/);
      }
    } else {
      restrictedActions = actions;
    }

    if (this.session || this.session.userAccess) {
      // TODO : check userAccess

      return yield next;
    }

    this.status = 403;
    this.body = 'Forbidden';
  };
}

/**
Deny only the given action to continue down the pipe. If a string is
specified, each action is separated by a space. If an array is specified, each
element is a defined action to allow.

@param {String|Array} actions     a list of actions to allow
@return {Function}                the middleware function
*/
function deny(actions) {
  if (typeof actions === 'string') {
    actions = actions.split(/\s+/);
  }

  return function * denyActions(next) {
    var restrictedActions;

    if (actions instanceof Function) {
      restrictedActions = yield actions.call(this);

      if (typeof restrictedActions === 'string') {
        restrictedActions = restrictedActions.split(/\s+/);
      }
    } else {
      restrictedActions = actions;
    }

    if (this.session || this.session.userAccess) {
      // TODO : check userAccess

      this.status = 403;
      this.body = 'Forbidden';
    }

    yield next;
  };
}
