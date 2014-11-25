var express = require('express')
    , router = express.Router();

/**
 * API routing.
 *
 * This router is used to manage the API routes.
 *
 */
exports = module.exports = function (user) {
    router.use('/user', user);

    return router;
};


/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'handlers/api/user' ];
