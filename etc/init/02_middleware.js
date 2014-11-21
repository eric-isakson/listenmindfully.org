/**
 * Module dependencies.
 */
var express = require('express')
    , path = require('path')
    , cookieParser = require('cookie-parser')
    , bodyParser = require('body-parser')
    , session = require('express-session');

/**
 * Initialize middleware.
 */
module.exports = function () {

    this.use(cookieParser());
    this.use(bodyParser.json());
    this.use(bodyParser.urlencoded({ extended: true }));
    this.use(this.router);
    this.use(express.static(path.join(__dirname, 'public')));
    this.use(express.errorHandler());

};
