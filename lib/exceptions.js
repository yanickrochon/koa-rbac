
var errorFactory = require('error-factory');

/**
Expose InvalidProviderException
*/
module.exports.InvalidOptionException = errorFactory('rbac.InvalidOptionException');

/**
Expose InvalidProviderException
*/
module.exports.InvalidRuleException = errorFactory('rbac.InvalidRuleException');
