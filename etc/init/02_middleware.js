/**
 * Module dependencies.
 */
var express = require('express')
    , path = require('path');

/**
 * Initialize middleware.
 */
module.exports = function () {

    this.use(express.urlencoded());
    this.use(express.json());
    this.use(this.router);
    this.use(express.static(path.join(__dirname, 'public')));
    this.use(express.errorHandler());

};
