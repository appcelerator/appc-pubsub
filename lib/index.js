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
	version = require('../package.json').version;

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

/**
 * get our interface information for both public and private
 */
function getIPAddresses (callback) {
	var pip = require('public-ip'),
		internalIP = require('internal-ip')();
	pip(function (err, publicIP) {
		callback(null, {
			publicAddress: publicIP || internalIP,
			privateAddress: internalIP || '127.0.0.1'
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
	Object.keys(obj).forEach(function (key) {
		var value = obj[key], t = typeof(value);
		if (t === 'function') {
			delete obj[key];
		}
		else if (t === 'object') {
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
	debug('publish', name);
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
	// push it back on top
	this.queue.unshift(opts);
	// reset the timer to run again with a small backoff each time
	this.timer = setTimeout(this._runQueue.bind(this), this.retry * 500);
	this.emit('requeue', reason, opts, this.retry);
	debug('requeue called', reason, opts);
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
				'User-Agent': 'Appcelerator PubSub Client/' + version,
				'APIKey': this.key,
				'APISig': crypto.createHmac('SHA256',this.secret).update(JSON.stringify(data)).digest('base64')
			},
			gzip: true,
			timeout: this.timeout,
			followAllRedirects: true,
			rejectUnauthorized: this.url.indexOf('360-local') < 0
		},
		self = this,
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
	this._drainQueue();
	if (this._socket && !this._shutdown) {
		debug('close sending disconnecting');
		this._socket.emit('disconnecting');
		this._shutdown = true;
		this._shutdownTimer = setTimeout(this._socket.close.bind(this._socket),2000);
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
	if (this._connecting) { return; }
	this._authed = false;
	this._connecting = true;
	this._connected = false;
	this._uuid = this._uuid || require('uuid-v4')();
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
		getIPAddresses(function (err, address) {
			socket.emit('authenticate', {
				uuid: self._uuid,
				key: self.key,
				signature: crypto.createHmac('SHA256',self.secret).update(self.key).digest('base64'),
				address: address
			});
			socket.on('authenticated', function () {
				if (self._authed) { return; }
				self._authed = true;
				debug('authenticated');
				socket.emit('register', toSubArray(self.eventSubscriptions));
				self._runQueue();
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
};

PubSubClient.prototype._connect = function(name) {
	if (this.disabled) { return; }
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
	if (name.indexOf(':') > 0) {
		this._connect(name);
	}
	return on.apply(this, arguments);
};

module.exports = PubSubClient;
