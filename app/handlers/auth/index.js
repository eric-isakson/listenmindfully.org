var express = require('express')
    , router = express.Router();

/**
 * Auth routing.
 *
 * This router is used to manage the auth routes.
 *
 */
exports = module.exports = function (login, link, unlink, logout) {
    // NOTE: The login callback route must match the callbacks defined in components/passport.setupStrategy()
    router.get('/login/:service', login);
    router.get('/login/:service/callback', login);
    router.get('/link/:service', link);
    router.get('/link/:service/callback', link);
    router.get('/unlink/:service', unlink);
    router.get('/logout', logout);
    // TODO add support for local signup and authentication

    return router;
};


/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'handlers/auth/login', 'handlers/auth/link', 'handlers/auth/unlink', 'handlers/auth/logout' ];
