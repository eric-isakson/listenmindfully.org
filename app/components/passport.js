/**
 * Module dependencies.
 */
var passport = require('passport')
    , FacebookStrategy = require('passport-facebook').Strategy
    , TwitterStrategy = require('passport-twitter').Strategy
    , GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

/**
 * Configure passport.
 *
 * This component configures the application's authentication mechanisms.
 */
exports = module.exports = function (logger, settings, User) {
    // TODO get settings specific to strategies rather than process.env
    // TODO log as each is setup

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function (id, done) {
        User.findById(id, function (err, user) {
            done(err, user);
        });
    });

    // =========================================================================
    // OAuth STRATEGIES ========================================================
    // =========================================================================
    function setupStrategy(Strategy, service, secrets, populate) {
        secrets.callbackURL = 'http://' + process.env.PUBLIC_HOST + '/auth/login/' + service + '/callback';
        secrets.passReqToCallback = true;
        passport.use(new Strategy(secrets,
            function (req, token, refreshToken, profile, done) {
                function populateAndSave(user) {
                    user.set(service + '.id', profile.id);
                    user.set(service + '.token', token);
                    populate(user, profile);
                    user.save(function (err) {
                        if (err) {
                            return done(err);
                        }

                        return done(null, user);
                    });
                }

                // asynchronous
                process.nextTick(function () {

                    // check if the user is already logged in
                    if (!req.user) {
                        var query = {};
                        query[service + '.id'] = profile.id;
                        User.findOne(query, function (err, user) {
                            if (err) {
                                return done(err);
                            }

                            if (user) {

                                // if there is a user id already but no token (user was linked at one point and then removed)
                                if (!user[service].token) {
                                    populateAndSave(user);
                                }

                                return done(null, user); // user found, return that user
                            } else {
                                // if there is no user, create them
                                populateAndSave(new User());
                            }
                        });

                    } else {
                        // user already exists and is logged in, we have to link accounts
                        populateAndSave(req.user); // pull the user out of the session
                    }
                });
            }
        ));
    }

    // =========================================================================
    // FACEBOOK ================================================================
    // =========================================================================
    setupStrategy(FacebookStrategy, 'facebook', {
            'clientID': process.env.FACEBOOK_CLIENT_ID,
            'clientSecret': process.env.FACEBOOK_CLIENT_SECRET
        },
        function (user, profile) {
            user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
            user.facebook.email = (profile.emails[0].value || '').toLowerCase();
            if (!user.displayName) {
                user.displayName = user.facebook.name;
            }
        }
    );

    // =========================================================================
    // TWITTER =================================================================
    // =========================================================================
    setupStrategy(TwitterStrategy, 'twitter', {
            'consumerKey': process.env.TWITTER_CLIENT_ID,
            'consumerSecret': process.env.TWITTER_CLIENT_SECRET
        },
        function (user, profile) {
            user.twitter.username = profile.username;
            user.twitter.displayName = profile.displayName;
            if (!user.displayName) {
                user.displayName = user.twitter.displayName;
            }
        }
    );

    // =========================================================================
    // GOOGLE ==================================================================
    // =========================================================================
    setupStrategy(GoogleStrategy, 'google', {
            'clientID': process.env.GOOGLE_CLIENT_ID,
            'clientSecret': process.env.GOOGLE_CLIENT_SECRET
        },
        function (user, profile) {
            user.google.name = profile.displayName;
            user.google.email = (profile.emails[0].value || '').toLowerCase(); // pull the first email
            if (!user.displayName) {
                user.displayName = user.google.name;
            }
        }
    );

    passport.scope = {
        'facebook': 'email',
        'google': ['profile', 'email'],
        'twitter': 'email'
    };


    return passport;
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
exports['@require'] = [ 'logger', 'settings', 'models/User' ];
