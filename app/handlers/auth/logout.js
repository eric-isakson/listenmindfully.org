/**
 * Logout handler.
 *
 * This route handler is used to logout the user.
 *
 */
exports = module.exports = function (isLoggedIn) {
    function logout(req, res) {
        req.logout();
        res.redirect('/');
    }

    return [
        isLoggedIn,
        logout
    ];
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'handlers/auth/isLoggedIn' ];
