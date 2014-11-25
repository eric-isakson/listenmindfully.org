/**
 * Authentication service supported handler.
 *
 * This route handler is used to verify that an authentication service with the route's service parameter is configured.
 *
 */
exports = module.exports = function (passport) {
    function isSupported(req, res, next) {
        if (!passport.scope.hasOwnProperty(req.params.service)) {
            next(new Error('Unknown authentication service: ' + req.params.service));
        }
        next();
    }

    return [
        isSupported
    ];
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'passport' ];
