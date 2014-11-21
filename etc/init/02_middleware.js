/**
 * Module dependencies.
 */
var express = require('express')
    , path = require('path')
    , cookieParser = require('cookie-parser')
    , bodyParser = require('body-parser')
    , methodOverride = require('method-override')
    , session = require('express-session');

/**
 * Initialize middleware.
 */
module.exports = function () {

    this.use(cookieParser());
    this.use(bodyParser.json());
    this.use(bodyParser.urlencoded({ extended: true }));
    this.use(methodOverride());
    this.use(express.static(path.join(__dirname, 'public')));

    // errors ======================================================================
    // catch 404 and forward to error handler
    this.use(function(req, res, next) {
        var err = new Error('Not Found');
        err.status = 404;
        next(err);
    });

    // error handlers

    // development error handler
    // will print stacktrace
    if (this.get('env') === 'development') {
        this.use(function (err, req, res, next) {
            res.status(err.status || 500);
            res.type('text');
            res.send(err.status + ' ' + err.message + '\n' + err.stack);
        });
    }

    // production error handler
    // no stacktraces leaked to user
    this.use(function (err, req, res, next) {
        res.status(err.status || 500);
        res.type('text');
        res.send(err.status + ' ' + err.message);
    });
};
