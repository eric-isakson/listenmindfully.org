/**
 * Module dependencies.
 */
var cookieParser = require('cookie-parser')
    , bodyParser = require('body-parser')
    , methodOverride = require('method-override');

/**
 * Initialize middleware.
 */
module.exports = function () {

    this.use(cookieParser());
    this.use(bodyParser.json());
    this.use(bodyParser.urlencoded({ extended: true }));
    this.use(methodOverride());

};
