/**
 * Module dependencies.
 */
var IoC = require('electrolyte')
    , express = require('express');


/**
 * Draw routes.
 *
 * Route handlers are created using Electrolyte, which automatically wires
 * together any necessary components, including database connections, logging
 * facilities, configuration settings, etc.
 */
module.exports = function routes() {
    // static content ==============================================================
    this.get('/', function(req, res, next) {
        if (!req.isAuthenticated()) {
            return res.redirect('login.html');
        }
        next();
    });
    this.use(express.static('public'));

    // authentication  =============================================================
    this.use('/auth', IoC.create('handlers/auth'));

    // APIs ========================================================================
    this.use('/api', IoC.create('handlers/api'));


    // catch 404 and forward to error handler ======================================
    this.use(function (req, res, next) {
        var err = new Error('Not Found');
        err.status = 404;
        next(err);
    });

    // errors ======================================================================

    // development error handler
    // will print stacktrace in response
    if (this.get('env') === 'development') {
        this.use(function (err, req, res) {
            res.status(err.status || 500);
            res.type('text');
            res.send(err.status + ' ' + err.message + '\n' + err.stack);
        });
    }

    // production error handler
    // no stacktraces leaked to user
    this.use(function (err, req, res) {
        // TODO provide a better error message experience if possible
        res.sendStatus(err.status || 500);
    });

};
