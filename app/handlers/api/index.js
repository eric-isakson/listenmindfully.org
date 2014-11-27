var express = require('express')
    , router = express.Router();

/**
 * API routing.
 *
 * This router is used to manage the API routes.
 *
 */
exports = module.exports = function (user, profile) {
    router.use('/user', user);
    router.use('/profile', profile);

    return router;
};


/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [
    'handlers/api/user',
    'handlers/api/profile'
];
