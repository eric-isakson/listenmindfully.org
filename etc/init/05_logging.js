/**
 * Module dependencies.
 */
var IoC = require('electrolyte')
    , expressWinston = require('express-winston');

/**
 * Initialize logging.
 */
module.exports = function () {
    var logger = IoC.create('logger');

    this.use(expressWinston.logger({
        transports: logger.transports,
        meta: true,
        msg: '{{res.statusCode}} {{req.method}} {{res.responseTime}}ms {{req.url}}',
        colorStatus: true
    }));

    // limit the logging information in the auth routes
    this.all('/auth', function (req, res, next) {
        req._routeWhitelists.req = [];
        req._routeWhitelists.body = [];
        req._routeWhitelists.res = ['_headers'];
        next();
    });

    this.use(expressWinston.errorLogger({
        transports: logger.transports
    }));
};
