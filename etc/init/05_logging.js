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
        winstonInstance: logger,
        meta: true,
        msg: '{{res.statusCode}} {{req.method}} {{res.responseTime}}ms {{req.url}}',
        colorStatus: true
    }));

    // TODO any limits we need on the logging information in the auth routes
//    this.all('/auth', function (req, res, next) {
//        req._routeWhitelists.req = [];
//        req._routeWhitelists.body = [];
//        req._routeWhitelists.res = [];
//        next();
//    });

    this.use(expressWinston.errorLogger({
        winstonInstance: logger,
    }));
};
