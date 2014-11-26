var winston = require('winston');

/**
 * Initialize logger.
 *
 * This component initializes the application's logger.
 */
exports = module.exports = function () {
    return new winston.Logger({
        transports: [
            new winston.transports.Console({
                colorize: true
            })
        ]
    });
};

/**
 * Component annotations.
 */
exports['@singleton'] = true;
