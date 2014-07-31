
var errorFactory = require('error-factory');

/**
Expose InvalidProviderException
*/
module.exports.InvalidProviderException = errorFactory('rbac.InvalidProviderException');

/**
Expose InvalidProviderException
*/
module.exports.InvalidRuleException = errorFactory('rbac.InvalidRuleException');
