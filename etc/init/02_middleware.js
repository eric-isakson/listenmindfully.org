/**
 * Module dependencies.
 */
var express = require('express')
    , cookieParser = require('cookie-parser')
    , bodyParser = require('body-parser')
    , methodOverride = require('method-override')
    , session = require('express-session');

/**
 * Initialize middleware.
 */
module.exports = function () {

    this.use(cookieParser());
    this.use(bodyParser.json());
    this.use(bodyParser.urlencoded({ extended: true }));
    this.use(methodOverride());

};
