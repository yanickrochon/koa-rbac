# Koa RBAC

Role-Based Access Control for [Koa](https://github.com/koajs/koa)

This module follows the [NIST RBAC model](http://en.wikipedia.org/wiki/NIST_RBAC_model)
and offer a flexible solution to allow or restrict user operations.


## Install

```
npm install koa-rbac --save
```


## Introduction

In an RBAC system, permissions are assigned to roles, not users. Therefore, roles
act as a ternary relation between permissions and users. Permissions are static,
defined in the applications. Roles, on the other hand, are dynamic and can be
defined from an application interface and saved in a datastore.

This module is not dependent on a authentication, a user session, or a datastore
system. The relation between the user and it's roles are specified by an
`AccessProvider`. It is the application's responsibility to implement such provider,
which requires at least only two methods; `getRolePermissions` and `getUserAccess`,
two methods returning the application's roles configuration and current user's roles
assignments respectively.

Rules are applied in consideration with the roles hierarchy. Top level roles always
have priority over inherited roles. This measn that, for example, given two roles :
`reader` and `editor`, respectively assigned the permissions `read` and `update`, and
where `editor` inherits from `reader`, a rule allowing `read`, but denying `update`
will validate if a user is an `editor`, but not a `reader`. If, `read` is instead
directly assigned to the `editor` role (inheriting `reader` or not), then the previous
rule would not validate for either an `editor` and a `reader` because `read` would
be a top level permission and has equal weight with the allowed permission.

When declaring rules on a resource, **allow** rules must be applied *before* the **deny**
ones; as any non-validating rule which do not have a greater weight than a valid
one will cause a `403 - Forbidden` error to be thrown.


## Usage

```javascript
// index.js

var rbac = require('koa-rbac');
var koa = require('koa');
var app = koa();
var AccessProvider = require('./access-provider');

app.use(rbac.middleware(new AccessProvider()));
app.use(rbac.allow('update'));
app.use(rbac.deny('read'));
app.use(function * (next) {
  this.body = "Allowed updating but not reading!";
});
```

```javascript
// access-provider.js

/**
Role cache. Normally, these would be stored in a database, or something
*/
var roles = {
  'guest': {
    //name: 'Guest'
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
    inherited: ['reader', 'editor']
  },
  'admin': {
    //name: 'Administrator',
    permissions: ['manage']
  }
};

module.exports = AccessProvider;

/**
AccessProvider constructor
*/
function AccessProvider() {
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
  return ['guest', 'reader'];
}
```


## Super User Role (Administrator)

This RBAC module does not have a built-in "administrator" role or permission. Such
privileged role must be implemented by the application. This can be achieved with
a role (ex: `admin`), with no inheritance, with a special permission (ex: `manage`),
and allow this special permission only and on every resource that has an *allow*`
or *deny* rule set.

This way, the special permission (ex: `manage`) can be assigned on other roles as
well, but may be denied, too, if necessary.


## Restricted access behaviour

When a rule fails (i.e. not allowed, or denied), each rule mddleware; `allow`
and `deny`, accept a second argument of type `string` that will send a redirect
(302 - Moved Temporarily) instead of returning an error (403 - Forbidden). For
example :

```javascript
var rbac = require('koa-rbac');
var koa = require('koa');
var app = koa();
var AccessProvider = require('./access-provider');

app.use(rbac.middleware(new AccessProvider()));
app.use(rbac.allow('update', '/login'));  // redirect to `/login` if not allowed
app.use(rbac.deny('read'));               // returns "Forbidden" if denied
app.use(function * (next) {
  this.body = "Allowed updating but not reading!";
});
```


## Contribution

All contributions welcome! Every PR **must** be accompanied by their associated
unit tests!


## License

The MIT License (MIT)

Copyright (c) 2014 Mind2Soft <yanick.rochon@mind2soft.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
