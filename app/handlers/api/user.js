var express = require('express')
    , router = express.Router();

/**
 * User routing.
 *
 * This router is used to manage the user API routes.
 *
 */
exports = module.exports = function (logger, settings, User) {

    router.head('/:id?', function (req, res) {
        if (!req.isAuthenticated()) {
            return res.sendStatus(403);
        }
        if (req.params.id) {
            if (req.params.id === 'current') {
                return res.sendStatus(200);
            }
            return res.sendStatus(403); // TODO implement user lookup and respond appropriately based on current user's permissions
        }
        res.sendStatus(403);
    });

    router.get('/:id?', function (req, res) {
        if (!req.isAuthenticated()) {
            logger.info("Unauthenticated request on the user API.");
            return res.sendStatus(403);
        }
        if (req.params.id) {
            logger.info("Get request for user: ", req.params.id);
            if (req.params.id === 'current') {
                return res.json(req.user);
            }
            return res.sendStatus(403); // TODO implement user lookup and respond appropriately based on current user's permissions
        }
        logger.info("Get request for users available to current user.");
        // TODO add verification checks and respond with a list of users the current user is authorized to see
        res.sendStatus(403);
    });

    return router;
};


/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'logger', 'settings', 'models/User' ];

