// route middleware to ensure user is logged in
exports = module.exports = function () {
    function isLoggedIn(req, res, next) {
        if (req.isAuthenticated()) {
            return next();
        }

        res.redirect('/');
    }

    return [
        isLoggedIn
    ];
};
/**
 * Component annotations.
 */
exports['@singleton'] = true;
