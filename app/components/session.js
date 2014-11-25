/**
 * Module dependencies.
 */
var mongoose = require('mongoose')
    , session = require('express-session')
    , mogooseSession = require('mongoose-session');

/**
 * Initialize the database connection and wires it as the express session store.
 *
 * This component configures the application's sessions.
 */
exports = module.exports = function (logger, settings) {
    // TODO get settings specific to session db rather than process.env
    // TODO log the connection attempt and handle errors
    var db = mongoose.connect(process.env.DB_URL, { server: { keepAlive: 1 } }); // connect to our database
    return session({
        key: 'session',
        // TODO use settings rather than process.env
        secret: process.env.SESSION_SECRET,
        store: mogooseSession(db)
    });
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'logger', 'settings' ];
