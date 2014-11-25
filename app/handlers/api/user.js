var express = require('express')
    , router = express.Router();

/**
 * User routing.
 *
 * This router is used to manage the user API routes.
 *
 */
exports = module.exports = function () {
    router.get('/:id?', function (req, res) {
        // TODO add verification checks and respond with a list of users the current user is authorized to see
        res.json(req.isAuthenticated() ? req.user : {});
    });

    return router;
};


/**
 * Component annotations.
 */
exports['@singleton'] = true;
