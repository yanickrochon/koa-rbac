# Koa RBAC

[![Build Status](https://travis-ci.org/yanickrochon/koa-rbac.svg)](https://travis-ci.org/yanickrochon/koa-rbac)[![Coverage Status](https://coveralls.io/repos/yanickrochon/koa-rbac/badge.svg?branch=master)](https://coveralls.io/r/yanickrochon/koa-rbac?branch=master)

Role-Based Access Control for [Koa](https://github.com/koajs/koa)

This module follows the [NIST RBAC model](http://en.wikipedia.org/wiki/NIST_RBAC_model) and offer a flexible solution to allow or restrict user operations.


## Install

```
npm install koa-rbac --save
```


## API

* **allow** *(permissions[, params[, redirect]])* - use this when specifying a rule that should only allow the current user with the given permissions. If the rule fails, the user will be redirected to the `redirectl` URL argument value, if specified, or an error `403` ("Forbidden") will be returned.
* **deny** *(permissions[, params[, redirect]])* - use this when specifying a rule that should restrict the current user with the given permissions. If the rule succeed (the user is denied), it will be redirected to the `redirect` URL argument value, if specified, or an error `403` ("Forbidden") will be returned.
* **check** *(objPermissions[, params[, redirect]])* - use this when specifying a combined allow/deny rule with the given permissions. The argument `objPermissions` should be an object declaring one or two keys (`'allow'` and/or `'deny'`) whose values are a set of permissions such as provided for the `allow` and `deny` methods. If the rule fails (i.e. the user is either not allowed, or denied), it will be redirected to the `redirect` URL argument value, if specified, or an error `403` ("Forbidden") will be thrown.

**Note**: the argument `permissions` (and the values of the `objPermissions` object) are either a string (i.e. a comma-separated list) or an array of permission values.


## Usage

```javascript
// index.js

const rbac = require('koa-rbac');
const koa = require('koa');
const app = koa();
const rules = require('path/to/rules');
const options = {
  rbac: new rbac.RBAC({
    provider: new rbac.RBAC.providers.JsonProvider(rules)
  })
  // identity: function (ctx) { return ctx && ctx.user } // passes `user` to rbac-a provider
};

app.use(rbac.middleware(options));
app.use(rbac.check({
  'allow': 'update',
  'deny': 'read'
}));
app.use(function (ctx) {
  ctx.body = "Allowed updating but not reading!";
});
```

**Note**: the argument `ctx` inside the identity function is the same value as `this` inside koa's middleware functions. For example, if using a session storage, such as [`koa-session`](https://github.com/koajs/session), it can be accessed through `ctx.session`.

See [rbac-a](https://www.npmjs.com/package/rbac-a) for more information.


## Contribution

All contributions welcome! Every PR **must** be accompanied by their associated unit tests!


## License

The MIT License (MIT)

Copyright (c) 2014 Mind2Soft <yanick.rochon@mind2soft.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
