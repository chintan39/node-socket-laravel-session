var crypto = require('crypto'),
    mcrypt = require('mcrypt'),
    mcryptCrypt = new mcrypt.MCrypt('rijndael-256', 'cbc'),
    phpunserialize = require('php-unserialize'),
    redis = require("redis"),
    util = require("util");

var self = {
	ord: function(string) {
	  var str = string + '',
	    code = str.charCodeAt(0);
	  if (0xD800 <= code && code <= 0xDBFF) {
	    var hi = code;
	    if (str.length === 1) {
	      return code;
	    }
	    var low = str.charCodeAt(1);
	    return ((hi - 0xD800) * 0x400) + (low - 0xDC00) + 0x10000;
	  }
	  if (0xDC00 <= code && code <= 0xDFFF) {
	    return code;
	  }
	  return code;
	},

	str_repeat: function(input, multiplier) {
	  var y = '';
	  while (true) {
	    if (multiplier & 1) {
	      y += input;
	    }
	    multiplier >>= 1;
	    if (multiplier) {
	      input += input;
	    } else {
	      break;
	    }
	  }
	  return y;
	},

	paddingIsValid: function(_pad, _value)
	{
	  beforePad = _value.length - _pad;
	  return _value.substr(beforePad) == self.str_repeat(_value.substr(-1), _pad);
	},

	stripPadding: function(_value)
	{
	  var len;
	  var pad = self.ord(_value[(len = _value.length) - 1]);
	  return self.paddingIsValid(pad, _value) ? _value.substr(0, _value.length - pad) : _value;
	},

	hash: function(_iv, _value, _key)
	{
	  return crypto.createHmac('sha256', _key).update(_iv + _value).digest('hex');
	},

	validMac: function(_key, _mac, _iv, _value)
	{
	  return(_mac == self.hash(_iv, _value, _key));
	},

	decryptSession: function(_key, _iv, _value) {
		mcryptCrypt.open(_key, _iv);
    	var decrypted = mcryptCrypt.decrypt(_value);
    	return phpunserialize.unserialize(self.stripPadding(decrypted.toString()));
	},

	getUserIdFromSessionId: function(_sessionId, _callback) {
		var client = redis.createClient();
		client.on("error", function (err) {
	        console.log("Error " + err);
	    });

		client.on("connect", function () {
		    console.log("Got connection.");
			console.log('laravel:'+_sessionId);

			setTimeout(function() {
				client.get('laravel:' + _sessionId, function(_err, _data) {
					if(_data) {
						// TODO: Fix this, this doesn't work as it should. Therefor using RegEx
						//var serializedData = phpunserialize.unserialize(_data.toString());

						var re = new RegExp('"id";s:[0-9]+:"[a-zA-Z0-9]+"');
						var m = re.exec(_data.toString());

						var re2 = new RegExp('[a-zA-Z0-9]{6,}');
						var m2 = re2.exec(m);

						_callback(m2);
					}
					client.end();
				});
			}, 1000);
		});
	}
};
module.exports = self;





