/**
 * Module dependencies.
 */
var helmet = require('helmet');

/**
 * Initialize security middleware.
 */
module.exports = function () {

    this.use(helmet());
    // TODO investigate if there are other security settings we should use
    // TODO review http://kroltech.com/2014/05/sanitizing-xss-and-html-with-express-middleware/#.VHQ5efnF-RI

};
