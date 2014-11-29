/**
 * Module dependencies.
 */
var mongoose = require('mongoose');

/**
 * Initialize the database connection and wires it as the express session store.
 *
 * This component configures the application's sessions.
 */
exports = module.exports = function (logger, settings, db) {
    // TODO get settings specific to session db rather than process.env
    // TODO log the connection attempt and handle errors
    // TODO store tokens on a different but related object, they should not be sent to the client as it is insecure
    var userSchema = mongoose.Schema({

        displayName: String,
        facebook: {
            id: String,
            token: String,
            email: String,
            name: String
        },
        twitter: {
            id: String,
            token: String,
            displayName: String,
            username: String
        },
        google: {
            id: String,
            token: String,
            email: String,
            name: String
        }

    });

    // create the model for users and expose it to our app
    return db.model('User', userSchema);
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'logger', 'settings', 'db/user' ];
