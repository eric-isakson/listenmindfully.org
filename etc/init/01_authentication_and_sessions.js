/**
 * Module dependencies.
 */
var IoC = require('electrolyte');

/**
 * Initialize session management and authentication.
 */
module.exports = function () {
    var passport = IoC.create('passport');

    this.use(IoC.create('session'));
    this.use(passport.initialize());
    this.use(passport.session()); // persistent login sessions
};
