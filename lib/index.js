'use strict';

const url = require('url');
const crypto = require('crypto');
const util = require('util');
const request = require('request');
const colors = require('colors');
const EventEmitter = require('events').EventEmitter;
const version = require('../package.json').version;

let debug = require('debug')('appc:pubsub');

let environments = {
		'production': 'https://pubsub.appcelerator.com',
		'preproduction': 'https://pubsub-preprod.cloud.appctest.com'
	},
	processExit = process.exit,
	events = [ 'exit', 'shutdown', 'SIGINT', 'SIGTERM' ],
	fingerprint;

/**
 * Checks process.env flags to determine if env is preproduction or developement.
 * @return {Boolean} flag if preproduction or development env
 */
function isPreproduction() {
	return process.env.NODE_ACS_URL
		&& process.env.NODE_ACS_URL.indexOf('.appctest.com') > 0
		|| process.env.NODE_ENV === 'preproduction'
		|| process.env.APPC_ENV === 'preproduction'
		|| process.env.NODE_ENV === 'development'
		|| process.env.APPC_ENV === 'development';
}

function sha1(value) {
	var crypto = require('crypto');
	var sha = crypto.createHash('sha1');
	sha.update(value);
	return sha.digest('hex');
}

/**
 * Gets unique fingerprint for the machine (hashed) which is used for server-side client id tracking.
 * @param {Function} callback
 * @param {String} append
 * @return {void}
 */
function getComputerFingerprint(callback, append) {
	if (fingerprint) {
		return callback && callback(null, fingerprint);
	}
	let exec = require('child_process').exec,
		cmd;
	switch (process.platform) {
		case 'darwin':
			// serial number + uuid is a good fingerprint
			// jscs:disable validateQuoteMarks
			cmd = 'ioreg -l | awk \'/IOPlatformSerialNumber/ { print $4 }\' | sed s/\\"//g && ioreg -rd1 -c IOPlatformExpertDevice |  awk \'/IOPlatformUUID/ { print $3; }\' | sed s/\\"//g;';
			debug('running:', cmd);
			return exec(cmd, function (err, stdout) {
				if (err) {
					return callback(err);
				}
				let tokens = stdout.trim().split(/\s/),
					serial = tokens[0],
					uuid = tokens[1];
				fingerprint = sha1(stdout + process.pid);
				callback && callback(null, fingerprint);
			});
		case 'win32':
		case 'windows':
			cmd = 'reg query HKLM\\Software\\Microsoft\\Cryptography /v MachineGuid';
			if (append) {
				cmd += append;
			}
			debug('running:', cmd);
			return exec(cmd, function (err, stdout) {
				if (err && !append) {
					debug('trying again, forcing it to use 64bit registry view');
					return getComputerFingerprint(callback, ' /reg:64');
				} else if (err) {
					return callback(err);
				}
				let tokens = stdout.trim().split(/\s/),
					serial = tokens[tokens.length - 1];
				fingerprint = sha1(serial + process.pid);
				callback && callback(null, fingerprint);
			});
		case 'linux':
			cmd = 'ifconfig | grep eth0 | grep -i hwaddr | awk \'{print $1$5}\' | sed \'s/://g\' | xargs echo | sed \'s/ //g\'';
			debug('running:', cmd);
			return exec(cmd, function (err, stdout) {
				if (err) {
					return callback(err);
				}
				let serial = stdout.trim();
				fingerprint = sha1(serial + process.pid);
				callback && callback(null, fingerprint);
			});
		default:
			return callback(new Error('Unknown platform:' + process.platform));
	}
}

/**
 * Get interface information for public and private addresses.
 * @param {Function} callback
 * @return {void}
 */
function getIPAddresses(callback) {
	getComputerFingerprint(function (err, fingerprint) {
		try {
			process.on('uncaughtException', console.error);
			let internalIP = require('ip').address();
			let pip = require('public-ip');
			pip.v4().then(function (publicIP) {
				process.removeListener('uncaughtException', console.error);
				callback(null, {
					publicAddress: publicIP || internalIP,
					privateAddress: internalIP || '127.0.0.1'
				}, fingerprint || Date.now());
			});
		}
		catch(e) {
			return callback(e);
		}
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
	opts.debug && (debug = function () {
		let args = Array.prototype.slice.call(arguments);
		if (args[0] && !!~args[0].indexOf('%')) {
			let result = util.format.apply(util.format, args);
			console.log('appc:pubsub'.red, result);
		} else {
			args.unshift('appc:pubsub'.red);
			console.log.apply(this, args);
		}
	});

	// prefer the environment settings over config
	let env = opts.env || (isPreproduction() ? 'preproduction' : 'production');
	this.url = opts.url || environments[env] || environments.production;

	// Require key and secret.
	this.disabled = opts.disabled;
	this.key = opts.key;
	this.secret = opts.secret;
	if (!this.disabled && !this.key) {
		throw new Error('missing key');
	}
	if (!this.disabled && !this.secret) {
		throw new Error('missing secret');
	}

	// Do not exit process on disconnect/close by default.
	this.exitOnError = opts.exitOnError || false;

	this.timeout = opts.timeout || 10000;
	this.queue = [];

	let self = this;
	if (opts.newrelic) {
		let newrelic = opts.newrelic;
		// on a requeue, we are going to send a custom metric to newrelic if configured
		this.on('requeue', function (code, opts, retries, length) {
			var message = code || 'Event requeue';
			var err = new Error(message);
			try {
				newrelic.noticeError(err, {
					key: opts.key,
					url: self.url,
					fingerprint: fingerprint,
					retrycount: retries,
					queuelength: length
				});
			} catch(e) {
				self.emit('error', e);
			}
		});
	}
	this.queueSendDelay = opts.queueSendDelay === undefined ? 10 : Math.max(1, +opts.queueSendDelay);
	getComputerFingerprint();
}

util.inherits(PubSubClient, EventEmitter);

/**
 * Returns fingerprint if set, or passes to callback, or generates fingerprint.
 * @param {Function} callback
 * @return {String} fingerprint
 */
PubSubClient.prototype.getFingerprint = function (callback) {
	if (fingerprint && callback) {
		return callback(null, fingerprint);
	} else if (fingerprint) {
		return fingerprint;
	} else if (callback) {
		return getComputerFingerprint(callback);
	}
	throw new Error('fingerprint has not yet been generated. invoke this function with a callback');
};

function serialize(obj, seen) {
	if (!obj || typeof(obj) !== 'object') {
		return obj;
	}
	if (obj instanceof RegExp) {
		return obj.source;
	}
	if (obj instanceof Date) {
		return obj;
	}
	Object.keys(obj).forEach(function (key) {
		var value = obj[key],
			t = typeof(value);
		if (t === 'function') {
			delete obj[key];
		} else if (/^(password|creditcard)/.test(key)) {
			// the server side does masking as well, but doesn't hurt to do it at origin
			obj[key] = '[HIDDEN]';
		} else if (value instanceof Date) {
			// do nothing
		} else if (value instanceof RegExp) {
			obj[key] = value.source;
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
 * @param {Object} options
 * @return {void}
 */
PubSubClient.prototype.publish = function (name, data, immediate, options) {
	if (this.disabled) {
		return;
	}
	debug('publish %s, immediate=%d', name, !!immediate);
	if (!name) {
		throw new Error('required event name');
	}
	if (Buffer.byteLength(name) > 255) {
		throw new Error('name length must be less than 255 bytes');
	}
	if (data && typeof(data) !== 'object') {
		throw new Error('data must be an object');
	}
	if (typeof(immediate) === 'object') {
		options = immediate;
		immediate = undefined;
	}
	// Clone data before serialization pass so objects are not modified.
	try {
		data = JSON.parse(JSON.stringify(data || {}));
	}
	catch(e) {
		throw new Error('data could not be cloned');
	}
	this.queue.push({
		event: name,
		data: serialize(data, []),
		options: options
	});
	// if we don't have a timer scheduled, run one near immediately
	if (!this.timer && !immediate) {
		this.timer = setTimeout(this._runQueue.bind(this), this.queueSendDelay);
	} else if (immediate) {
		this._runQueue();
	}
};

/**
 * Requeue events.
 *
 * @private
 * @param {String} reason
 * @param {Object} opts
 */
PubSubClient.prototype._requeue = function (reason, opts) {
	debug('requeue called', reason, opts);
	if (this.disabled || this._closing) {
		debug('requeue ignored, disabled=%d, closing=%d', !!this.disabled, !!this._closing, new Error().stack);
		return;
	}
	// push it back on top
	this.queue.unshift(opts);
	// reset the timer to run again with a small backoff each time
	this.timer = setTimeout(this._runQueue.bind(this), Math.max(500, this.retry * 500));
	this.emit('requeue', reason, opts, this.retry, this.queue.length);
};

/**
 * Run queue for sending events to the server.
 *
 * @private
 * @param {Boolean} closing
 * @return {void}
 */
PubSubClient.prototype._runQueue = function (closing) {
	if (this.disabled) {
		return false;
	}
	debug('_runQueue');
	let self = this;
	if (!fingerprint) {
		// fetch the fingerprint and re-run this method again
		getComputerFingerprint(function () {
			self._runQueue();
		});
		return false;
	}
	// reset the timer
	this.timer && clearTimeout(this.timer);
	this.timer = null;
	// no events, just return
	if (this.queue.length === 0) {
		return;
	}
	this.retry = (this.retry || 0) + 1;
	// pop off the pending event in the queue FIFO
	let data = this.queue.shift();
	// shouldn't get here, but empty data slot
	if (!data) {
		return;
	}

	this._sending = true;
	let ticket = Date.now();
	this._sendingTS = ticket;

	let opts = {
		url: url.resolve(this.url, '/api/event'),
		method: 'post',
		json: data,
		headers: {
			'User-Agent': 'Appcelerator PubSub Client/' + version + ' (' + fingerprint + ')',
			'APIKey': this.key,
			'APISig': crypto.createHmac('SHA256', this.secret).update(JSON.stringify(data)).digest('base64')
		},
		gzip: true,
		timeout: this.timeout,
		followAllRedirects: true,
		rejectUnauthorized: !!~this.url.indexOf(environments.production.split('.').slice(-2).join('.'))
	};

	try {
		debug('sending web event', opts);
		let req = request(opts);
		// handle response
		req.on('response', function (resp) {
			// check current and if the same, change state, otherwise a new event has come
			// in since we got here
			if (ticket === self._sendingTS) {
				self._sending = false;
			}
			debug('received web response', resp && resp.statusCode);
			if (resp && resp.statusCode !== 200) {
				// an error which isn't a security error, try to push again
				if (resp.statusCode && !(/^(400|401)$/).test(resp.statusCode)) {
					return self._requeue(resp.statusCode, data);
				}
				let err = new Error('invalid response'),
					closeAfterFire = false;
				err.code = resp.statusCode;
				// if 401 that means the apikey, secret is wrong. disable before raising an error
				if (resp.statusCode === 401) {
					err.message = 'Unauthorized';
					closeAfterFire = true;
					self.emit('unauthorized', err, opts);
				}
				debug('error', err, resp.statusCode, resp.body);
				if (closeAfterFire) {
					self.close();
					self.disabled = true;
					process.exit = processExit;
				}
			} else if (resp) {
				// reset our retry count on successfully sending
				self.retry = 0;
				// emit an event
				self.emit('response', resp, opts);
				// if we still have pending events to send, re-queue to run again
				if (self.queue.length) {
					process.nextTick(self._drainQueue.bind(self));
				}
				debug('response received, status=%d, opts=%j', resp.statusCode, opts);
			}
		});
		// handle HTTP errors
		req.on('error', function (err) {
			debug('web request received error', err, opts);
			// check current and if the same, change state, otherwise a new event has come
			// in since we got here
			if (ticket === self._sendingTS) {
				self._sending = false;
			}
			if (self._closing) {
				return self.close();
			}
			return self._requeue(err.code, opts);
		});
	}
	catch(E) {
		debug('web request received error', E, opts);
		self._requeue(E.code, opts);
	}
	return this.queue.length;
};

/**
 * Drain queue.
 *
 * @private
 * @param {Boolean} closing
 */
PubSubClient.prototype._drainQueue = function (closing) {
	if (this.disabled) {
		return;
	}
	debug('_drainQueue %d', this.queue.length);
	let start = Date.now();
	while (this.queue.length > 0 && (Date.now() - start < 10000)) {
		if (!this._runQueue(closing)) {
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

PubSubClient.prototype.close = function () {
	if (this.disabled) {
		return;
	}
	debug('close, closed=%d, closing=%d, sending=%d', !!this._closed, !!this._closing, !!this._sending);
	let self = this;
	if (!this._closed && !this._closing) {
		this._drainQueue(true);
	}
	if (!this._closing) {
		this._closing = Date.now();
		if (!this._closingTimer) {
			clearTimeout(this._closingTimer);
			this._closingTimer = setTimeout(function () {
				debug('closing timer has fired');
				self._sending = false;
				self.queue = [];
				self.close();
				self.exitOnError && process.exit();
			}, 10000);
		}
	}
	if (this._sending && !this._shutdown) {
		debug('close is waiting to connect, delay, sending=%d', this._sending);
		if (this._shutdownTimer) {
			return true;
		}
		setTimeout(function () {
			// attempt to close again immediately
			self.close();
		}, 500);
		this._shutdownTimer = setTimeout(function () {
			debug('shutdown #1 timer has fired');
			self._shutdown = self._sending =  false;
			self._closed = true; // force close if we haven't received it yet
			self.close();
			self.exitOnError && process.exit();
		}, 5000);
		return true;
	}
	this._closed = true;
	let shutdownHandler = this._shutdownHandler;
	if (this._shutdownHandler) {
		events.forEach(function (signal) {
			try {
				process.removeListener(signal, self._shutdownHandler);
			} catch(e) {}
		});
		this._shutdownHandler = null;
	}
	if (processExit && process.exit !== processExit) {
		process.exit = processExit;
	}
	if (this._shutdownTimer) {
		clearTimeout(this._shutdownTimer);
		this._shutdownTimer = null;
	}
	if (this._closingTimer) {
		clearTimeout(this._closingTimer);
		this._closingTimer = null;
	}
	debug('close queue length=', this.queue.length);
	debug('close pendingExit (%d)', this._pendingExit);
	this._shutdown = this._closed = true;
	this._closing = false;
	if (this._pendingExit) {
		debug('calling process.exit(%d)', this._pendingExitCode);
		this.exitOnError && processExit(this._pendingExitCode);
	}
	return this.queue.length;
};

let on = PubSubClient.prototype.on;
PubSubClient.prototype.on = function (name) {
	debug('on %s', name);
	return on.apply(this, arguments);
};

module.exports = PubSubClient;
