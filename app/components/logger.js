function Logger() {
}

Logger.prototype.log = function (msg) {
    console.log(msg);
};

Logger.prototype.info = function (msg) {
    console.info(msg);
};

Logger.prototype.warn = function (msg) {
    console.warn(msg);
};

Logger.prototype.error = function (msg) {
    console.error(msg);
};

/**
 * Initialize logger.
 *
 * This component initializes the application's logger.
 */
exports = module.exports = function () {
    return new Logger();
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
