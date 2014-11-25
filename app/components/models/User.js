/**
 * Module dependencies.
 */
var mongoose = require('mongoose')
    , bcrypt = require('bcrypt-nodejs');

/**
 * Initialize the database connection and wires it as the express session store.
 *
 * This component configures the application's sessions.
 */
exports = module.exports = function (logger, settings, db) {
    // TODO get settings specific to session db rather than process.env
    // TODO log the connection attempt and handle errors
    var userSchema = mongoose.Schema({

        local: {
            email: String,
            password: String
        },
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
    // generating a hash
    userSchema.methods.generateHash = function (password) {
        return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
    };

    // checking if password is valid
    userSchema.methods.validPassword = function (password) {
        return bcrypt.compareSync(password, this.local.password); // TODO not sure about "this" context here
    };

    // create the model for users and expose it to our app
    return db.model('User', userSchema);
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'logger', 'settings', 'db/user' ];
