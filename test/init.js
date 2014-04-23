
if (!process.env.TRAVIS) {
  if (typeof __cov === 'undefined') {
    process.on('exit', function () {
      require('semicov').report();
    });
  }

  require('semicov').init('lib');
}

// setting globals
GLOBAL.assert = global.assert = require('assert');
