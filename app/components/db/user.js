/**
 * Module dependencies.
 */
var mongoose = require('mongoose');

/**
 * Initialize database connection.
 *
 * This component configures the application's user database.
 */
exports = module.exports = function (logger, settings) {
    // TODO get settings specific to user db rather than process.env
    // TODO log the connection attempt and handle errors
    return mongoose.createConnection(process.env.DB_URL, { server: { keepAlive: 1 } }); // connect to our database
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'logger', 'settings' ];
