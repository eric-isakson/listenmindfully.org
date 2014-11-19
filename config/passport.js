// load all the things we need
var LocalStrategy    = require('passport-local').Strategy
    , FacebookStrategy = require('passport-facebook').Strategy
    , TwitterStrategy  = require('passport-twitter').Strategy
    , GoogleStrategy   = require('passport-google-oauth').OAuth2Strategy
    , User       = require('../app/models/user');

module.exports = function(passport) {

    var localStrategyArgs = {
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    }

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    passport.use('local-login', new LocalStrategy(localStrategyArgs,
    function(req, email, password, done) {
        if (email)
            email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

        // asynchronous
        process.nextTick(function() {
            User.findOne({ 'local.email' :  email }, function(err, user) {
                // if there are any errors, return the error
                if (err)
                    return done(err);

                // if no user is found, return the message
                if (!user)
                    return done(null, false, req.flash('loginMessage', 'No user found.'));

                if (!user.validPassword(password))
                    return done(null, false, req.flash('loginMessage', 'Wrong password.'));

                // all is well, return user
                else
                    return done(null, user);
            });
        });

    }));

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    passport.use('local-signup', new LocalStrategy(localStrategyArgs,
    function(req, email, password, done) {
        if (email)
            email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

        function populateAndSave(flashKey, user) {
            User.findOne({ 'local.email' :  email }, function(err, foundUser) {
                if (err)
                    return done(err);

                if (foundUser) {
                    return done(null, false, req.flash(flashKey, 'That email is already taken.'));
                } else {
                    user.local.email = email;
                    user.local.password = user.generateHash(password);
                    user.save(function (err) {
                        if (err)
                            return done(err);

                        return done(null,user);
                    });
                }
            });
        }

        // asynchronous
        process.nextTick(function() {
            // if the user is not already logged in:
            if (!req.user) {
                populateAndSave('signupMessage', new User());
            // if the user is logged in but has no local account...
            } else if ( !req.user.local.email ) {
                // ...presumably they're trying to connect a local account
                // BUT let's check if the email used to connect a local account is being used by another user
                populateAndSave('loginMessage', req.user);
                // Using 'loginMessage instead of signupMessage because it's used by /connect/local'
            } else {
                // user is logged in and already has a local account. Ignore signup. (You should log out before trying to create a new account, user!)
                return done(null, req.user);
            }

        });

    }));

    // =========================================================================
    // OAuth STRATEGIES ========================================================
    // =========================================================================
    function setupStrategy(Strategy, service, secrets, populate) {
        secrets.callbackURL = 'http://' + process.env.PUBLIC_HOST + '/auth/' + service + '/callback';
        secrets.passReqToCallback = true;
        passport.use(new Strategy(secrets,
            function (req, token, refreshToken, profile, done) {
                function populateAndSave(user) {
                    user[service + ".id"] = profile.id;
                    user[service + ".token"] = token;
                    populate(user, profile);
                    user.save(function (err) {
                        if (err)
                            return done(err);

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
                            if (err)
                                return done(err);

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
    setupStrategy(FacebookStrategy, "facebook", {
            'clientID' 		: process.env.FACEBOOK_CLIENT_ID,
            'clientSecret' 	: process.env.FACEBOOK_CLIENT_SECRET
        },
        function (user, profile) {
            user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
            user.facebook.email = (profile.emails[0].value || '').toLowerCase();
        }
    );

    // =========================================================================
    // TWITTER =================================================================
    // =========================================================================
    setupStrategy(TwitterStrategy, "twitter", {
            'consumerKey' 		: process.env.TWITTER_CLIENT_ID,
            'consumerSecret' 	: process.env.TWITTER_CLIENT_SECRET
        },
        function (user, profile) {
            user.twitter.username    = profile.username;
            user.twitter.displayName = profile.displayName;
        }
    );

    // =========================================================================
    // GOOGLE ==================================================================
    // =========================================================================
    setupStrategy(GoogleStrategy, "google", {
            'clientID' 		: process.env.GOOGLE_CLIENT_ID,
            'clientSecret' 	: process.env.GOOGLE_CLIENT_SECRET
        },
        function (user, profile) {
            user.google.name  = profile.displayName;
            user.google.email = (profile.emails[0].value || '').toLowerCase(); // pull the first email
        }
    );
};
