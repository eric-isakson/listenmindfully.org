/**
 * Login handler.
 *
 * This route handler is used to initiate an OAuth handshake with a passport authentication service when there is not a currently logged in user.
 *
 */
exports = module.exports = function (passport, isSupported) {
    function login(req, res) {
        if (!/\/callback$/.test(req.path)) {
            passport.authenticate(req.params.service, { scope: passport.scope[req.params.service] });
        }
        else {
            passport.authenticate(req.params.service, function (req, res) {
                // TODO is this the same original request/response pair?
                res.redirect('/');
            });
        }
    }

    return [
        isSupported,
        login
    ];
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'passport', 'handlers/auth/isSupported' ];
