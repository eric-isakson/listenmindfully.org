/**
 * First route always goes through this handler for every request.
 *
 * This route handler is used to log all requests to the application.
 *
 * Parameters:
 *
 *   - `logger`  Logger for logging warnings, errors, etc.
 */
exports = module.exports = function (logger, settings) {
    function logRequest(req, res, next) {
        var message = req.ip + ' ' + req.path + ' ' + req.headers['user-agent'];
        if (settings.get('env') === 'development') {
            for (var header in req.headers) {
                if (req.headers.hasOwnProperty(header)) {
                    message += '\n' + header + '=' + req.headers[header];
                }
            }
        }
        logger.info(message);
        next();
    }

    return [
        logRequest
    ];
};

/**
 * Component annotations.
 */
exports['@require'] = [ 'logger', 'settings' ];
