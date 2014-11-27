var express = require('express')
    , router = express.Router();

/**
 * Profile routing.
 *
 * This router is used to manage the profile API routes.
 *
 */
exports = module.exports = function () {
    router.get('/', function (req, res) {
        // TODO add a profile schema to the db and model and lookup the profile for the current user, for now, just respond with the current user
        // respond with an empty object when the user is not logged in, this is used during application bootstrapping
        var profile = {};

        if (req.isAuthenticated()) {
            profile.user = req.user; // TODO is there info here that shouldn't be sent to the client?
        }

        res.json(profile);
    });

    return router;
};


/**
 * Component annotations.
 */
exports['@singleton'] = true;
