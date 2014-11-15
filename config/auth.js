// config/auth.js

// expose our config directly to our application using module.exports
module.exports = {

	'facebookAuth' : {
		'clientID' 		: process.env.FACEBOOK_CLIENT_ID,
		'clientSecret' 	: process.env.FACEBOOK_CLIENT_SECRET,
		'callbackURL' 	: 'http://' + process.env.PUBLIC_HOST + '/auth/facebook/callback'
	},

	'twitterAuth' : {
		'consumerKey' 		: process.env.TWITTER_CLIENT_ID,
		'consumerSecret' 	: process.env.TWITTER_CLIENT_SECRET,
		'callbackURL' 		: 'http://' + process.env.PUBLIC_HOST + '/auth/twitter/callback'
	},

	'googleAuth' : {
		'clientID' 		: process.env.GOOGLE_CLIENT_ID,
		'clientSecret' 	: process.env.GOOGLE_CLIENT_SECRET,
		'callbackURL' 	: 'http://' + process.env.PUBLIC_HOST + '/auth/google/callback'
	}

};