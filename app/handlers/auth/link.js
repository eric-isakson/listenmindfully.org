/**
 * Account linking handler.
 *
 * This route handler is used to initiate an OAuth handshake with a passport authorization service to connect multiple accounts to a single User.
 *
 */
exports = module.exports = function (passport, isLoggedIn, isSupported) {
    function link(req, res) {
        if (!/\/callback$/.test(req.path)) {
            passport.authorize(req.params.service, { scope: passport.scope[req.params.service] });
        }
        else {
            passport.authorize(req.params.service, function (req, res) {
                // TODO is this the same original request/response pair?
                res.json(req.user);
            });
        }
    }

    return [
        isLoggedIn,
        isSupported,
        link
    ];
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'passport', 'handlers/auth/isLoggedIn', 'handlers/auth/isSupported' ];
