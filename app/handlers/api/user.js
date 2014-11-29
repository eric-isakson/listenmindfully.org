var express = require('express')
    , router = express.Router();

/**
 * User routing.
 *
 * This router is used to manage the user API routes.
 *
 */
exports = module.exports = function () {

    router.head('/:id?', function (req, res) {
        if (!req.isAuthenticated()) {
            res.sendStatus(403);
        }
        if (req.params.id) {
            if (req.params.id === 'current') {
                res.sendStatus(200);
            }
            else {
                res.sendStatus(403); // TODO implement user lookup and respond appropriately based on current user's permissions
            }
        }
        res.sendStatus(403);
    });

    router.get('/:id?', function (req, res) {
        if (!req.isAuthenticated()) {
            res.sendStatus(403);
        }
        if (req.params.id) {
            if (req.params.id === 'current') {
                res.json(req.user);
            }
            else {
                res.sendStatus(403); // TODO implement user lookup and respond appropriately based on current user's permissions
            }
        }
        // TODO add verification checks and respond with a list of users the current user is authorized to see
        res.sendStatus(403);
    });

    return router;
};


/**
 * Component annotations.
 */
exports['@singleton'] = true;
