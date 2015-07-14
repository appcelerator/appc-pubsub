var url = require('url'),
	crypto = require('crypto'),
	util = require('util'),
	request = require('request'),
	debug = require('debug')('appc:pubsub'),
	EventEmitter = require('events').EventEmitter,
	environments = {
		'production': 'https://pubsub.appcelerator.com',
		'preproduction': 'https://pubsub-preprod.cloud.appctest.com'
	},
	version = require('../package.json').version,
	processExit = process.exit,
	fingerprint;

/**
 * utility to determine if we're running in production
 */
function isRunningInPreproduction() {
	return process.env.NODE_ACS_URL &&
		process.env.NODE_ACS_URL.indexOf('.appctest.com') > 0 ||
		process.env.NODE_ENV === 'preproduction' ||
		process.env.APPC_ENV === 'preproduction' ||
		process.env.NODE_ENV === 'development' ||
		process.env.APPC_ENV === 'development';
}

function sha1(value) {
	var crypto = require('crypto');
	var sha = crypto.createHash('sha1');
	sha.update(value);
	return sha.digest('hex');
}

/**
 * get a unique fingerprint for the machine (hashed) which is used for
 * server-side client id tracking
 */
function getComputerFingerprint (callback, append) {
	if (fingerprint) { return callback(null, fingerprint); }
	var exec = require('child_process').exec,
		cmd;
	switch (process.platform) {
		case 'darwin':
			// serial number + uuid is a good fingerprint
			// jscs:disable validateQuoteMarks
			cmd = "ioreg -l | awk '/IOPlatformSerialNumber/ { print $4 }' | sed s/\\\"//g && ioreg -rd1 -c IOPlatformExpertDevice |  awk '/IOPlatformUUID/ { print $3; }' | sed s/\\\"//g;";
			debug('running:', cmd);
			return exec(cmd, function (err, stdout) {
				if (err) { return callback(err); }
				var tokens = stdout.trim().split(/\s/),
					serial = tokens[0],
					uuid = tokens[1];
				fingerprint = sha1(stdout);
				return callback(null, fingerprint);
			});
		case 'win32':
		case 'windows':
			cmd = 'reg query HKLM\\Software\\Microsoft\\Cryptography /v MachineGuid';
			if (append) { cmd += append; }
			debug('running:', cmd);
			return exec(cmd, function (err, stdout) {
				if (err && !append) {
					debug('trying again, forcing it to use 64bit registry view');
					return getComputerFingerprint(callback, ' /reg:64');
				} else if (err) {
					return callback(err);
				}
				var tokens = stdout.trim().split(/\s/),
					serial = tokens[tokens.length - 1];
				fingerprint = sha1(serial);
				return callback(null, fingerprint);
			});
		case 'linux':
			cmd = "ifconfig | grep eth0 | grep -i hwaddr | awk '{print $1$5}' | sed 's/://g' | xargs echo | sed 's/ //g'";
			debug('running:', cmd);
			return exec(cmd, function (err, stdout) {
				if (err) { return callback(err); }
				var serial = stdout.trim();
				fingerprint = sha1(serial);
				callback(null, fingerprint);
			});
		default:
			callback(new Error("Unknown platform:" + process.platform));
	}
}

/**
 * get our interface information for both public and private
 */
function getIPAddresses (callback) {
	var pip = require('public-ip'),
		internalIP = require('internal-ip')();
	getComputerFingerprint(function (err, fingerprint) {
		pip(function (err, publicIP) {
			callback(null, {
				publicAddress: publicIP || internalIP,
				privateAddress: internalIP || '127.0.0.1'
			}, fingerprint || Date.now());
		});
	});
}

/**
 * Class constructor
 *
 * @class PubSubClient
 * @param {Object} opts options for configuring the client
 */
function PubSubClient(opts) {
	opts = opts || {};
	var env = opts.env || isRunningInPreproduction() ? 'preproduction' : 'production';
	this.timeout = opts.timeout || 10000;
	this.url = opts.url || environments[env] || environments.production;
	this.key = opts.key;
	this.secret = opts.secret;
	this.queue = [];
	if (!this.key) {
		throw new Error('missing key');
	}
	if (!this.secret) {
		throw new Error('missing secret');
	}
	this.disabled = opts.disabled;
	this.queueSendDelay = opts.queueSendDelay === undefined ? 10 : Math.max(1,+opts.queueSendDelay);
	this.preferWebSocket = opts.preferWebSocket === undefined ? false : opts.preferWebSocket;
	// if we prefer web socket transport, then go ahead and connect
	if (this.preferWebSocket) {
		process.nextTick(this._reconnect.bind(this));
	}
}

util.inherits(PubSubClient, EventEmitter);

function serialize(obj, seen) {
	if (!obj || typeof(obj)!=='object') { return obj; }
	if (obj instanceof RegExp) { return obj.source; }
	Object.keys(obj).forEach(function (key) {
		var value = obj[key], t = typeof(value);
		if (t === 'function') {
			delete obj[key];
		} else if (/^(password|creditcard)/.test(key)) {
			// the server side does masking as well, but doesn't hurt to do it at origin
			obj[key] = '[HIDDEN]';
		} else if (t === 'object') {
			if (seen.indexOf(value) !== -1) {
				value = '[Circular]';
			} else {
				seen.push(value);
				value = serialize(value, seen);
			}
			obj[key] = value;
		}
	});
	return obj;
}

/**
 * publish an event with name and optional data
 * @param {String} name name of the event
 * @param {Object} data optional event payload or undefined/null if no event data
 * @param {Boolean} immediate don't queue it, send it immediately
 */
PubSubClient.prototype.publish = function (name, data, immediate) {
	if (this.disabled) { return; }
	debug('publish %s, immediate=%d', name, !!immediate);
	if (!name) {
		throw new Error('required event name');
	}
	if (data && typeof(data)!=='object') {
		throw new Error('data must be an object');
	}
	this.queue.push({
		event: name,
		data: serialize(data, [])
	});
	// if we don't have a timer scheduled, run one near immediately
	if (!this.timer && !immediate && !this._connecting) {
		if (this._connected && !this._authed) {
			// we are connected, waiting for auth so we should wait for that to finishs
			return;
		}
		// otherwise go ahead and schedule a timer to run
		this.timer = setTimeout(this._runQueue.bind(this), this.queueSendDelay);
	} else if (immediate) {
		this._runQueue();
	}
};

/**
 * internal method to requeue an event
 */
PubSubClient.prototype._requeue = function (reason, opts) {
	if (this.disabled) { return; }
	debug('requeue called', reason, opts);
	// push it back on top
	this.queue.unshift(opts);
	// reset the timer to run again with a small backoff each time
	this.timer = setTimeout(this._runQueue.bind(this), this.retry * 500);
	this.emit('requeue', reason, opts, this.retry);
};

/**
 * common handler for errors
 */
function createErrorHandler (self, opts) {
	return function pubsubRequetErrorHandler(err) {
		if (/^(ETIMEDOUT|ENOTFOUND|ECONNREFUSED)$/.test(err.code)) {
			return self._requeue(err.code, opts);
		}
		self.emit('error', err, opts);
		debug('error called', err, opts);
	};
}

/**
 * internal method to run the queue for sending events to the server
 *
 * @private
 */
PubSubClient.prototype._runQueue = function () {
	if (this.disabled) { return; }
	debug('_runQueue');
	var self = this;
	if (!fingerprint) {
		// fetch the fingerprint and re-run this method again
		return getComputerFingerprint(function() {
			self._runQueue();
		});
	}
	// reset the timer
	if (this.timer) { clearTimeout(this.timer); }
	this.timer = null;
	// no events, just return
	if (this.queue.length===0) { return; }
	this.retry = (this.retry || 0) + 1;
	// pop off the pending event in the queue FIFO
	var data = this.queue.shift();
	// shouldn't get here, but empty data slot
	if (!data) { return; }

	// if we prefer to send via web socket and we're connected, use it
	if (this.preferWebSocket && this._socket && this._authed && this._connected) {
		debug('sending socket event', data);
		return this._socket.emit('event', data);
	}
	var opts = {
			url: url.resolve(this.url, '/api/event'),
			method: 'post',
			json: data,
			headers: {
				'User-Agent': 'Appcelerator PubSub Client/' + version + ' (' + fingerprint + ')',
				'APIKey': this.key,
				'APISig': crypto.createHmac('SHA256',this.secret).update(JSON.stringify(data)).digest('base64')
			},
			gzip: true,
			timeout: this.timeout,
			followAllRedirects: true,
			rejectUnauthorized: this.url.indexOf('360-local') < 0
		},
		handler = createErrorHandler(this, data);

	try {
		debug('sending web event', opts);
		var req = request(opts);
		// handle response
		req.on('response',function (resp) {
			if (resp && resp.statusCode!==200) {
				// an error which isn't a security error, try to push again
				if (resp && resp.statusCode && !/^(400|401)$/.test(resp.statusCode)) {
					return self._requeue(resp.statusCode, data);
				}
				var err = new Error('invalid response');
				err.code = resp.statusCode;
				self.emit('error', err, opts);
				debug('error', err);
			} else if (resp) {
				// reset our retry count on successfully sending
				self.retry = 0;
				// emit an event
				self.emit('response', resp, opts);
				// if we still have pending events to send, re-queue to run again
				if (self.queue.length) {
					process.nextTick(self._runQueue.bind(self));
				}
				debug('response received, status=%d, opts=%j', resp.statusCode, opts);
			}
		});
		// handle HTTP errors
		req.on('error', handler);
	}
	catch (E) {
		handler(E);
	}
	return this.queue.length;
};

/**
 * drain the queue
 */
PubSubClient.prototype._drainQueue = function() {
	if (this.disabled) { return; }
	debug('_drainQueue %d', this.queue.length);
	var start = Date.now();
	while (this.queue.length > 0 && (Date.now() - start < 10000)) {
		if (!this._runQueue()) {
			break;
		}
	}
};

function toSubArray(value) {
	var array = [];
	value && Object.keys(value).forEach(function (i) {
		array.push(value[i].source);
	});
	return array;
}

PubSubClient.prototype._deliver = function(event) {
	if (this.disabled) { return; }
	debug('deliver', event);
	Object.keys(this.eventSubscriptions).forEach(function (subid) {
		var pattern = this.eventSubscriptions[subid];
		if (pattern.test(event.event)) {
			this.emit(subid, event);
		}
	}.bind(this));
};

PubSubClient.prototype.close = function() {
	if (this.disabled) { return; }
	debug('close');
	var self = this;
	this._closed = true;
	this._drainQueue();
	if (this._connecting && !this._shutdown) {
		debug('close is waiting to connect, delay');
		setTimeout(function() {
			self._shutdown = false;
			self._closed = true; // force close if we haven't received it yet
			self.close();
		},2000);
		return true;
	}
	if (this._socket && !this._shutdown) {
		debug('close sending disconnecting');
		this._socket.emit('disconnecting');
		this._shutdown = true;
		this._shutdownTimer = setTimeout(function() {
			self._socket.close();
			self._socket = null;
			self.close();
		},2000);
		return true;
	}
	this._connected = this._connecting = this._authed = false;
	this.removeAllListeners();
	if (this._socket) {
		this._shutdown = true;
		this._socket.close();
		this._socket = null;
	}
	clearInterval(this._socketKA);
	this._socketKA = null;
	if (this._shutdownHandler) {
		process.removeEventListener('exit', this._shutdownHandler);
		process.removeEventListener('SIGINT', this._shutdownHandler);
		this._shutdownHandler = null;
	}
	if (processExit) {
		process.exit = processExit;
	}
	if (this._shutdownTimer) {
		clearTimeout(this._shutdownTimer);
		this._shutdownTimer = null;
	}
	debug('close queue length=',this.queue.length);
	return this.queue.length;
};

function createDisconnectHandler(self, socket, reconnect) {
	return function disconnectHandler(reason, message) {
		debug('disconnect', reason, message, reconnect);
		var delay;
		if (self._shutdownTimer) {
			debug('cancelling shutdown timer');
			clearTimeout(self._shutdownTimer);
			self._shutdownTimer = null;
		}
		if (!reason && !reconnect) {
			delay = self.close();
		}
		if (reason && reason !== 'unauthorized') {
			if (!self._connecting && reconnect && !self._shutdown) {
				self._reconnect();
			}
		} else if (reason) {
			var err = new Error(message);
			err.code = reason;
			self.emit('error',err);
		}
		if (self._shutdownHandler) {
			process.removeListener('exit', self._shutdownHandler);
			process.removeListener('SIGINT', self._shutdownHandler);
			self._shutdownHandler = null;
		}
		if (self._disconnectHandler) {
			socket.removeListener('disconnecting', self._disconnectHandler);
			socket.removeListener('disconnect', self._disconnectHandler);
			self._disconnectHandler = null;
		}
		if (!reconnect) {
			if (delay) {
				setTimeout(process.exit, 2000);
			} else {
				process.exit();
			}
		}
	};
}

PubSubClient.prototype._reconnect = function() {
	if (this.disabled) { return; }
	debug('_reconnect');
	if (this._connecting || this._closed) { return; }
	this._authed = false;
	this._connecting = true;
	this._connected = false;
	this._socketKA = setInterval(function () {
	}, 60000);
	var socket = this._socket = require('socket.io-client')(this.url);
	var self = this;
	debug('connecting uuid=%s, url=%s', this._uuid, this.url);
	socket.on('connect', function() {
		// we can get multiple notices so we ignore after first
		if (self._connected) { return; }
		debug('connected');
		self._connected = true;
		self._connecting = false;
		self._shutdown = false;
		// if closed before fully auth, just return
		getIPAddresses(function (err, address, fingerprint) {
			socket.emit('authenticate', {
				uuid: fingerprint, // used to uniquely identify this client
				key: self.key,
				signature: crypto.createHmac('SHA256',self.secret).update(self.key).digest('base64'),
				address: address
			});
			socket.on('authenticated', function () {
				if (self._authed || self._closed) { return; }
				self._authed = true;
				debug('authenticated');
				socket.emit('register', toSubArray(self.eventSubscriptions));
				self._runQueue();
			});
			socket.on('ping', function () {
				debug('received ping');
				socket.emit('pong');
			});
		});
	});
	socket.on('event', this._deliver.bind(this));
	this._disconnectHandler = createDisconnectHandler(this, socket, true);
	this._shutdownHandler = createDisconnectHandler(this, socket, false);
	socket.on('disconnecting', this._disconnectHandler);
	socket.on('disconnect', this._disconnectHandler);
	process.on('exit', this._shutdownHandler);
	process.on('SIGINT', this._shutdownHandler);
	// hook exit to allow our queue to drain
	process.exit = function (ec) {
		if (!self._shutdown) {
			process.emit('exit', ec);
		} else if (processExit) {
			processExit(ec);
		}
	};
};

PubSubClient.prototype._connect = function(name) {
	if (this.disabled) { return; }
	debug('_connect %s', name);
	var i = name.indexOf(':'),
		pattern = name.substring(i+1);

	this.eventSubscriptions = this.eventSubscriptions || {};
	this.eventSubscriptions[name] = new RegExp(pattern);

	if (!this._connected) {
		this._reconnect();
	} else if (this._socket && this._authed) {
		this._socket.emit('register', toSubArray(this.eventSubscriptions));
	}
};

var on = PubSubClient.prototype.on;
PubSubClient.prototype.on = function(name) {
	debug('on %s', name);
	if (name.indexOf(':') > 0) {
		this._connect(name);
	}
	return on.apply(this, arguments);
};

module.exports = PubSubClient;
