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
			pip(function (err, publicIP) {
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
		// on a requeue, we are going to send a custom metric to newrelic if configured
		this.on('connect_error', function (err) {
			try {
				newrelic.noticeError(err, {
					key: opts.key,
					url: self.url,
					fingerprint: fingerprint
				});
			} catch(e) {
				self.emit('error', e);
			}
		});
	}
	this.queueSendDelay = opts.queueSendDelay === undefined ? 10 : Math.max(1, +opts.queueSendDelay);
	this.preferWebSocket = opts.preferWebSocket === undefined ? false : opts.preferWebSocket;
	getComputerFingerprint();

	// if we prefer web socket transport, then go ahead and connect
	if (this.preferWebSocket) {
		this._pendingStart = true;

		function localExit(ec) {
			if (self._pendingStart) {
				debug('process.exit called but pending start, will exit on connect');
				self._pendingStartExit = true;
				self._pendingStartExitCode = ec;
				return;
			}
			debug('process exit called');
			processExit.apply(this, arguments);
		};

		process.exit = localExit;
		process.nextTick(function () {
			self._reconnect();
			self._pendingStart = false;
			if (process.exit === localExit) {
				debug('resetting process.exit');
				process.exit = processExit;
			}
			if (self._pendingStartExit) {
				debug('pending start, we exited');
				process.exit(self._pendingStartExitCode);
			}
		});
	}
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

	// if we prefer to send via web socket and we're connected, use it
	if (this.preferWebSocket && this._socket && this._authed && this._connected) {
		debug('sending socket event', data);
		this._socket.emit('event', data);
		return process.nextTick(function () {
			// check current and if the same, change state, otherwise a new event has come
			// in since we got here
			if (ticket === self._sendingTS) {
				self._sending = false;
			}
			// if we still have pending events to send, re-queue to run again
			if (self.queue.length) {
				process.nextTick(self._drainQueue.bind(self));
			}
		});
	}
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
				self._connecting = false;
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

PubSubClient.prototype._deliver = function (event) {
	if (this.disabled) {
		return;
	}
	debug('deliver', event);
	Object.keys(this.eventSubscriptions).forEach(function (subid) {
		var pattern = this.eventSubscriptions[subid];
		if (pattern.test(event.event)) {
			this.emit(subid, event);
		}
	}.bind(this));
};

PubSubClient.prototype.close = function () {
	if (this.disabled) {
		return;
	}
	debug('close, closed=%d, closing=%d, connecting=%d, sending=%d, authed=%d', !!this._closed, !!this._closing, !!this._connecting, !!this._sending, !!this._authed);
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
				self._sending = self._connecting = false;
				self.queue = [];
				self.close();
				self.exitOnError && process.exit();
			}, 10000);
		}
	}
	if ((this._connecting || this._sending) && !this._shutdown) {
		debug('close is waiting to connect, delay, connecting=%d, sending=%d', this._connecting, this._sending);
		if (this._shutdownTimer) {
			return true;
		}
		setTimeout(function () {
			// attempt to close again immediately
			self.close();
		}, 500);
		this._shutdownTimer = setTimeout(function () {
			debug('shutdown #1 timer has fired');
			self._shutdown = self._sending = self._connecting = false;
			self._closed = true; // force close if we haven't received it yet
			self.close();
			self.exitOnError && process.exit();
		}, 5000);
		return true;
	}
	this._closed = true;
	if (this._socket && !this._shutdown) {
		this._shutdown = true;
		if (this._connected && !this._closed) {
			if (this._shutdownTimer) {
				return true;
			}
			debug('close sending disconnecting');
			this._socket.emit('disconnecting');
			this._shutdownTimer = setTimeout(function () {
				debug('shutdown #2 timer has fired');
				self._shutdown = self._sending = self._connecting = false;
				self._closed = true; // force close if we haven't received it yet
				self.close();
				self.exitOnError && process.exit();
			}, 5000);
			return true;
		}
	}
	this._connected = this._connecting = this._authed = false;
	this.removeAllListeners();
	if (this._socket) {
		this._socket.close();
		this._socket = null;
	}
	clearInterval(this._socketKA);
	this._socketKA = null;
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

function createDisconnectHandler(self, socket, reconnect) {
	return function disconnectHandler(reason, message) {
		debug('disconnect, reason: %s, message: %s, reconnect: %s, pending exit: %s', reason, message, reconnect, !!self._pendingExit);
		if (self._closing && !self._closed) {
			debug('already closing, ignore disconnect');
			return;
		}
		let serverDisconnect = reason === 'io server disconnect';
		if (self._pendingStart && !serverDisconnect) {
			self._pendingStartExit = true;
			self._pendingStartExitCode = reason;
			self._pendingExit = true;
			debug('pending start, ignore disconnect');
			setTimeout(function () {
				self.emit('disconnecting');
				disconnectHandler(reason, message);
			}, self._sending ? 3000 : 1000);
			return;
		}
		let delay;
		if (!reconnect && !self._pendingExit && !serverDisconnect) {
			self._pendingExit = true;
			if (socket && !reason) {
				if (self._sending) {
					return;
				}
				socket.emit('disconnecting');
				return setTimeout(function () {
					disconnectHandler(reason, message);
				}, self._sending ? 3000 : 1000);
			}
		}
		if (!reason && !reconnect || serverDisconnect) {
			delay = self.close();
		}
		if (reason && reason !== 'unauthorized' && !serverDisconnect) {
			if (!self._connecting && reconnect && !self._shutdown) {
				self._reconnect();
			}
		} else if (reason && !serverDisconnect) {
			let err = new Error(message);
			err.code = reason;
			self.emit('error', err);
		}
		// Force reconnect
		if (reconnect) {
			self._reconnect();
		}
		if (self._shutdownHandler) {
			events.forEach(function (signal) {
				try {
					process.removeListener(signal, self._shutdownHandler);
				} catch(e) {}
			});
			self._shutdownHandler = null;
		}
		if (self._disconnectHandler) {
			socket.removeListener('disconnecting', self._disconnectHandler);
			socket.removeListener('disconnect', self._disconnectHandler);
			self._disconnectHandler = null;
		}
	};
}

PubSubClient.prototype._reconnect = function () {
	if (this.disabled) {
		return;
	}
	debug('_reconnect');
	if (this._connecting) {
		debug('_reconnect called but connecting=%d', !!this._connecting);
		return;
	}
	this._authed = false;
	this._connecting = true;
	this._connected = false;
	clearInterval(this._socketKA);
	this._socketKA = setInterval(function () {
	}, 60000);
	if (this._socket) {
		debug('closing existing socket', this._socket);
		this._socket.close();
	}
	let socket = this._socket = require('socket.io-client')(this.url, { forceNew:true });
	let self = this;
	debug('connecting url=%s', this.url);
	socket.on('connect', function () {
		debug('connected');
		// we can get multiple notices so we ignore after first
		if (self._connected) {
			return;
		}
		self._connected = true;
		self._connecting = false;
		self._shutdown = false;
		// if closed before fully auth, just return
		getIPAddresses(function (err, address, fingerprint) {
			socket.emit('authenticate', {
				uuid: fingerprint, // used to uniquely identify this client
				key: self.key,
				signature: crypto.createHmac('SHA256', self.secret).update(self.key).digest('base64'),
				address: address
			});
			socket.on('authenticated', function () {
				self._authed = true;
				debug('authenticated');
				socket.emit('register', toSubArray(self.eventSubscriptions));
				self._runQueue();
			});
			socket.on('pubsub:ping', function () {
				debug('received ping, sending pong');
				socket.emit('pubsub:pong');
			});
		});
	});
	socket.io.on('connect_error', function (data) {
		self.emit('connect_error', data);
	});
	socket.on('event', this._deliver.bind(this));
	if (this._shutdownHandler) {
		events.forEach(function (signal) {
			try {
				process.removeListener(signal, self._shutdownHandler);
			} catch(e) {}
		});
	}
	this._disconnectHandler = createDisconnectHandler(this, socket, true);
	this._shutdownHandler = createDisconnectHandler(this, socket, false);
	socket.on('disconnecting', this._disconnectHandler);
	socket.on('disconnect', this._disconnectHandler);
	events.forEach(function (signal) {
		process.on(signal, self._shutdownHandler);
	});
	if (process.exit !== processExit) {
		// hook exit to allow our queue to drain
		process.exit = function (ec) {
			debug('process.exit, exitcode=%d, shutdown=%d, emitexit=%d', ec, !!self._shutdown, !!self._emitexit);
			self._pendingExit = true;
			if (!self._shutdown && !self._emitexit) {
				self._pendingExitCode = ec === undefined ? 0 : ec;
				self._emitexit = true;
				try {
					// don't let it fail
					debug('emitting shutdown event');
					process.emit('shutdown');
				}
				catch(E) {
					debug('received error on exit', E.stack);
					self.exitOnError && processExit(ec);
				}
			} else if (processExit && self.exitOnError && self._shutdown) {
				ec = ec === undefined ? 0 : ec;
				debug('calling process.exit (%d)', ec);
				processExit(ec);
			}
		};
	}
};

PubSubClient.prototype._connect = function (name) {
	if (this.disabled) {
		return;
	}
	debug('_connect %s', name);
	let i = name.indexOf(':'),
		pattern = name.substring(i + 1);

	this.eventSubscriptions = this.eventSubscriptions || {};
	this.eventSubscriptions[name] = new RegExp(pattern);

	if (!this._connected) {
		this._reconnect();
	} else if (this._socket && this._authed) {
		this._socket.emit('register', toSubArray(this.eventSubscriptions));
	}
};

let on = PubSubClient.prototype.on;
PubSubClient.prototype.on = function (name) {
	debug('on %s', name);
	if (name.indexOf(':') > 0) {
		this._connect(name);
	}
	return on.apply(this, arguments);
};

module.exports = PubSubClient;
