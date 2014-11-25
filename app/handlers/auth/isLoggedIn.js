// route middleware to ensure user is logged in
module.exports = function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }

    res.redirect('/');
};
/**
 * Component annotations.
 */
exports['@singleton'] = true;
