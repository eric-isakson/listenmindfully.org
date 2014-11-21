/**
 * First route always goes through this handler for every request.
 *
 * This route handler is used to log all requests to the application.
 *
 * Parameters:
 *
 *   - `logger`  Logger for logging warnings, errors, etc.
 */
exports = module.exports = function(logger) {

    function logRequest(req, res, next) {
        logger.info(req.ip + ' ' + req.path + ' ' + req.headers['user-agent']);
        next();
    }

    return [
        logRequest
    ];
}

/**
 * Component annotations.
 */
exports['@require'] = [ 'logger' ];
