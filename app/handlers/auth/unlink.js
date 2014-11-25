/**
 * Unlink handler.
 *
 * This route handler is used to disconnect an account from the current user.
 *
 */
exports = module.exports = function (isLoggedIn, isSupported) {
    function unlink(req, res, next) {
        var user = req.user;
        user.get(req.params.service).token = undefined;
        user.save(function (err) {
            if (err) {
                next(err);
            }
            res.json(req.user);
        });
        // TODO if this is last service on logged in user, log them out at this point
    }

    return [
        isLoggedIn,
        isSupported,
        unlink
    ];
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'handlers/auth/isLoggedIn', 'handlers/auth/isSupported' ];
