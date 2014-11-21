/**
 * Module dependencies.
 */
var fs = require('fs')

// constants
var CONF_FILE = 'etc/conf.json';


/**
 * Initialize settings.
 *
 * This component configures the application's settings.
 */
exports = module.exports = function() {
  var settings = new Settings();
  
  settings.set('env', process.env.NODE_ENV || 'development');

  if (fs.existsSync(CONF_FILE)) {
    var data = fs.readFileSync(CONF_FILE, 'utf8');
    var json = JSON.parse(data);
    for (var name in json) {
        settings.set(name, json[name]);
    }
  }
  
  return settings;
}

/**
 * Component annotations.
 */
exports['@singleton'] = true;




function Settings() {
  this._hash = {};
}

Settings.prototype.get = function(key) {
  return this._hash[key];
}

Settings.prototype.set = function(key, val) {
  this._hash[key] = val;
}
