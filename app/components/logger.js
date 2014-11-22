function Logger() {
}

Logger.prototype.log = function (msg) {
    console.log(message('LOG', msg));
};

Logger.prototype.info = function (msg) {
    console.info(message('INFO', msg));
};

Logger.prototype.warn = function (msg) {
    console.warn(message('WARN', msg));
};

Logger.prototype.error = function (msg) {
    console.error(message('ERROR', msg));
};

function message(level, msg) {
    return level + ' ' + timeStamp() + ' ' + msg;
}

/**
 * Return a timestamp with the format "m/d/yy h:MM:ss TT"
 * @return {string}
 */

function timeStamp() {
    // Create a date object with the current time
    var now = new Date();

    // Create an array with the current month, day and time
    var date = [ now.getMonth() + 1, now.getDate(), now.getFullYear() ];

    // Create an array with the current hour, minute and second
    var time = [ now.getHours(), now.getMinutes(), now.getSeconds() ];

    // Determine AM or PM suffix based on the hour
    var suffix = ( time[0] < 12 ) ? 'AM' : 'PM';

    // Convert hour from military time
    time[0] = ( time[0] < 12 ) ? time[0] : time[0] - 12;

    // If hour is 0, set it to 12
    time[0] = time[0] || 12;

    // If seconds and minutes are less than 10, add a zero
    for (var i = 1; i < 3; i++) {
        if (time[i] < 10) {
            time[i] = '0' + time[i];
        }
    }

    // Return the formatted string
    return date.join('/') + ' ' + time.join(':') + ' ' + suffix;
}

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
