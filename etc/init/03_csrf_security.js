/**
 * Module dependencies.
 */
var csrf = require('csurf');

/**
 * Initialize Cross-site request forgery protection middleware.
 */
module.exports = function () {

    this.use(csrf());

    // error handler
    this.use(function (err, req, res, next) {
        if (err.code !== 'EBADCSRFTOKEN') {
            return next(err);
        }
        err.status = 403; // Forbidden
        next(err);
    });
};
