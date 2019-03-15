'use strict';

const basicAuth = require('basic-auth');
const exec = require('child_process').exec;
const url = require('url');
const crypto = require('crypto');
const util = require('util');
const request = require('request');
const EventEmitter = require('events').EventEmitter;
const version = require('../package.json').version;

const environments = {
	production: 'https://pubsub.platform.axway.com',
	preproduction: 'https://pubsub.axwaytest.net'
};
const preproductionEnvironments = [ 'preproduction', 'development' ];

let fingerprint;
let pendingChecks = [];
let debug;

/**
 * Checks process.env flags to determine if env is preproduction or developement.
 * @return {Boolean} flag if preproduction or development env
 */
function isPreproduction() {
	return String(process.env.NODE_ACS_URL).includes('.appctest.com')
		|| String(process.env.NODE_ACS_URL).includes('.axwaytest.net')
		|| preproductionEnvironments.includes(process.env.NODE_ENV)
		|| preproductionEnvironments.includes(process.env.APPC_ENV);
}

/**
 * Returns sha1 digested value.
 * @param {String} value value to digest
 * @returns {String} digested value
 */
function sha1(value) {
	return crypto
		.createHash('sha1')
		.update(value)
		.digest('hex');
}

/**
 * Gets unique fingerprint for the machine (hashed) which is used for server-side client id tracking.
 * @param {Function} callback the callback function
 * @param {String} append append to command
 * @return {void}
 */
function getComputerFingerprint(callback, append) {
	if (fingerprint) {
		return callback && callback(null, fingerprint);
	}

	let cmd;
	switch (process.platform) {
		case 'darwin':
			// serial number + uuid is a good fingerprint
			cmd = 'ioreg -c IOPlatformExpertDevice -d 2 | awk -F\\" \'/IOPlatformSerialNumber|IOPlatformUUID/{ print $(NF-1) }\';';
			debug('running:', cmd);
			return exec(cmd, function (err, stdout) {
				if (err) {
					return callback(err);
				}
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
 * Class constructor
 *
 * @class PubSubClient
 * @param {Object} opts options for configuring the client
 */
function PubSubClient(opts) {
	opts = opts || {};

	// Stub debug logging function and extend if enabled.
	debug = function () {};
	opts.debug && (debug = function () {
		let args = Array.prototype.slice.call(arguments);
		args.unshift('appc:pubsub');
		console.log.apply(this, args);
	});

	// prefer the environment settings over config
	let env = opts.env || (isPreproduction() ? 'preproduction' : 'production');
	this.url = opts.url || environments[env] || environments.production;

	// Require key and secret.
	this.disabled = opts.disabled;
	this.key = opts.key;
	this.secret = opts.secret;

	if (this.disabled) {
		return;
	}
	if (!this.key) {
		throw new Error('missing key');
	}
	if (!this.secret) {
		throw new Error('missing secret');
	}

	this.timeout = opts.timeout || 10000;

	getComputerFingerprint();
	this.fetchConfig();
	// These functions need the client binding for use as a middleware/route
	this.authenticateWebhook = this.authenticateWebhook.bind(this);
	this.handleWebhook = this.handleWebhook.bind(this);

	this.queue = [];
	this.batchTimeoutHandler = null;
	this.batching = Object.assign(opts.batching || {}, {
		maxWait: 1000 // 1s
	});
}

util.inherits(PubSubClient, EventEmitter);

/**
 * Fetch client config from the server.
 * @param {Function} callback the callback function
 */
PubSubClient.prototype.fetchConfig = function () {
	// some random data to sign for the signature
	let data = {},
		opts = {
			url: url.resolve(this.url, '/api/client/config'),
			method: 'get',
			json: data,
			headers: {
				'User-Agent': 'Appcelerator PubSub Client/' + version + ' (' + fingerprint + ')',
				APIKey: this.key,
				APISig: crypto.createHmac('SHA256', this.secret).update(JSON.stringify(data)).digest('base64')
			},
			gzip: true,
			timeout: this.timeout,
			followAllRedirects: true,
			rejectUnauthorized: this.url.includes(environments.production.split('.').slice(-2).join('.'))
		};
	debug('fetching client config');
	this.config = {};
	request(opts, function (err, resp, body) {
		if (err) {
			return debug('error', err);
		}
		let data = body && body[body.key];

		if (!data || resp.statusCode !== 200) {
			let err = new Error('invalid response');
			err.code = resp.statusCode;
			// if 401 that means the apikey, secret is wrong. disable before raising an error
			if (resp.statusCode === 401) {
				err.message = 'Unauthorized';
				this.emit('unauthorized', err, opts);
			}
			return debug('error', err, resp.statusCode, resp.body);
		}

		this._parseConfig(data);

		this.on('configured', () => pendingChecks.forEach(this._validateTopic.bind(this)));
		this.emit('configured', this.config);
		debug('got config', this.config);
	}.bind(this));
};

PubSubClient.prototype._parseConfig = function (data) {
	if (data.can_consume) {
		// Extract topic from keys of event map.
		data.topics = Object.keys(data.events || {});

		// Get basic auth creds from the url
		if (data.auth_type === 'basic' && data.url) {
			let details = (url.parse(data.url) || '').auth.split(':');
			data.auth_user = details[0];
			data.auth_pass = details[1];
		}
	}
	this.config = data;
};

/**
 * Authenticates a webhook request as being from pubsub server. Can be used as middleware.
 * @param {http.ClientRequest} req request object containing auth details
 * @param {http.ServerResponse} [res] response object for responding with errors
 * @param {Function} [next] optional callback function for use in middleware
 * @return {Boolean} whether the request is authenticated
 */
PubSubClient.prototype.authenticateWebhook = function (req, res, next) {
	if (req._authenticatedWebhook) {
		next && next();
		return true;
	}
	// Make sure the client has consumption enabled
	if (!this.config.can_consume) {
		res && res.writeHead(400, { 'Content-Type': 'application/json' });
		res && res.end(JSON.stringify({
			success: false,
			message: 'This client does not have consumption enabled.'
		}));
		return false;
	}
	debug('authenticating webhook using: method =', this.config.auth_type);

	let conf = this.config,
		headers = req && req.headers || {},
		user = basicAuth(req),
		// Validate request using clients authentication method
		authenticated
			// Check the basic auth credentials match...
			= conf.auth_type === 'basic'
				? user.name === conf.auth_user && user.pass === conf.auth_pass
				// ...or the request has the correct auth token
				: conf.auth_type === 'token'
					? headers['x-auth-token'] === this.config.auth_token
					// ...or the signature matches the body signed with the client secret
					: conf.auth_type === 'key_secret'
						? headers['x-signature'] === crypto.createHmac('SHA256', this.secret).update(JSON.stringify(req.body)).digest('hex')
						// ...otherwise there's no authentication for the client
						: true;

	// Make sure the request is from pubsub server
	if (!authenticated) {
		debug('webhook authentication failed', headers);
		res && res.writeHead(401, { 'Content-Type': 'application/json' });
		res && res.end(JSON.stringify({
			success: false,
			message: 'Unauthorized'
		}));
		return false;
	}
	req._authenticatedWebhook = true;
	next && next();
	return true;
};

/**
 * Webhook handler route that exposes events using the EventEmitter pattern.
 * @param {http.ClientRequest} req Request object
 * @param {http.ServerResponse} res Response object
 */
PubSubClient.prototype.handleWebhook = function (req, res) {
	// Make sure the request has been authenticated
	if (!this.authenticateWebhook(req, res)) {
		return;
	}

	let topic = req.body.topic;
	debug('event received', topic, req.body);

	// Search for any configured regex matches and emit using those too
	if (this.getSubscribedTopic(topic)) {
		debug('emitting event:' + topic);
		this.emit('event:' + topic, req.body);
	}

	res.writeHead(200, { 'Content-Type': 'application/json' });
	res.end(JSON.stringify({ success: true }));
};

/**
 * Validates that event name is in client's subscribed topics (or provided topic list).
 * @param {String} name topic/event name
 * @param {Array} topics (optional) set of topics to validate against, defaults to this.config.topics
 * @returns {Boolean} true if event matched topics
 */
PubSubClient.prototype.getSubscribedTopic = function (name, topics) {
	// Event names are prefixed, so strip it.
	name = name.replace('event:', '');
	// Add internal events since they will be emitted.
	let validTopics = [ 'configured', 'unauthorized' ].concat(topics || this.config.topics || []);
	return validTopics.find(topic => {
		// Name matches topic
		if (topic === name) {
			return topic;
		}
		// Fall out if exact match missed and topic does not have wildcard.
		if (!topic.includes('*')) {
			return null;
		}
		let eventSegments = name.split('.');
		let topicSegments = topic.split('.');
		// Fall out if topic is not double-splatted and segment counts do not match.
		if (!topic.includes('**') && eventSegments.length !== topicSegments.length) {
			return null;
		}
		// Check if name matches topic segment checks.
		return topicSegments.reduce(function (m, segment, i) {
			return m && (
				// segment matched
				segment === eventSegments[i]
				// segment was wildcarded
				|| segment === '*'
				// segment was terminus and double-splatted
				|| (segment === '**' && i === topicSegments.length - 1)
			);
		}, true);
	}) || null;
};

/**
 * Returns fingerprint if set, or passes to callback, or generates fingerprint.
 * @param {Function} callback the callback function
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
		} else if (value && t === 'object') {
			if (seen.includes(value)) {
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
 * @param {Object} options the options object
 * @return {void}
 */
PubSubClient.prototype.publish = function (name, data, options) {
	if (this.disabled) {
		return;
	}
	debug('publish', name);
	if (!name) {
		throw new Error('required event name');
	}
	if (Buffer.byteLength(name) > 255) {
		throw new Error('name length must be less than 255 bytes');
	}
	if (data && typeof(data) !== 'object') {
		throw new Error('data must be an object');
	}
	// Clone data before serialization pass so objects are not modified.
	try {
		data = JSON.parse(JSON.stringify(data || {}));
	} catch (e) {
		throw new Error('data could not be cloned');
	}

	// add to the staging queue
	this.queue.push({
		event: name,
		data: serialize(data, []),
		options: options
	});

	// trigger timeout to flush queued events
	if (!this.batchTimeoutHandler) {
		this.batchTimeoutHandler = setTimeout(
			this._publish.bind(this),
			this.batching.maxWait
		);
	}
};

/**
 * Publishes a batch of events.
 *
 * @private
 */
PubSubClient.prototype._publish = function () {
	const events = this.queue;

	clearTimeout(this.batchTimeoutHandler);
	this.batchTimeoutHandler = null;
	this.queue = [];

	events.forEach(event => {
		this._send(event);
	});
};

/**
 * Retry event.
 *
 * @private
 * @param {Object} data the data object
 * @param {String} reason the retry reason
 * @param {Object} opts the options object
 */
PubSubClient.prototype._retry = function (data, reason, opts) {
	debug('retry called', reason, opts);
	if (this.disabled) {
		debug('retry ignored, disabled:', !!this.disabled, new Error().stack);
		return;
	}
	// run again with a small backoff each time
	setTimeout(() => this._send(data), Math.max(500, this.retry * 500));
	this.emit('retry', reason, opts, this.retry);
};

/**
 * Sending event to the server.
 *
 * @private
 * @param {Object} data the data object
 * @return {void}
 */
PubSubClient.prototype._send = function (data) {
	if (this.disabled) {
		return false;
	}

	debug('_send', data);
	let self = this;
	if (!fingerprint) {
		// fetch the fingerprint and re-run this method again
		getComputerFingerprint(() => this._send.apply(this, arguments));
		return false;
	}

	this.retry = (this.retry || 0) + 1;
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
			APIKey: this.key,
			APISig: crypto.createHmac('SHA256', this.secret).update(JSON.stringify(data)).digest('base64')
		},
		gzip: true,
		timeout: this.timeout,
		followAllRedirects: true,
		rejectUnauthorized: this.url.includes(environments.production.split('.').slice(-2).join('.'))
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
					return self._retry(data, resp.statusCode);
				}
				let err = new Error('invalid response');
				err.code = resp.statusCode;
				// if 401 that means the apikey, secret is wrong. disable before raising an error
				if (resp.statusCode === 401) {
					err.message = 'Unauthorized';
					self.emit('unauthorized', err, opts);
				}
				debug('error', err, resp.statusCode, resp.body);
			} else if (resp) {
				// reset our retry count on successfully sending
				self.retry = 0;
				// emit an event
				self.emit('response', resp, opts);
				debug('response received, status:', resp.statusCode, 'opts:', opts);
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
			return self._retry(data, err.code, opts);
		});
	} catch (E) {
		debug('web request received error', E, opts);
		self._retry(data, E.code, opts);
	}
};

let on = PubSubClient.prototype.on;
PubSubClient.prototype.on = function (name) {
	debug('on', name);
	// If the topics have been fetched then we can attempt to warn about events
	// that aren't configured to be received by this client
	if (!this.configued) {
		pendingChecks.push(name);
	} else {
		this._validateTopic(name);
	}
	return on.apply(this, arguments);
};

PubSubClient.prototype._validateTopic = function (name) {
	if (!this.getSubscribedTopic(name)) {
		debug('Unexpected event', name, ': client not configured to receive this event');
	}
};

/**
 * Stub deprecated close function.
 */
PubSubClient.prototype.close = function () {
	debug('pubsub.close function has been deprecated. Websocket connections are no longer supported.');
};

module.exports = PubSubClient;
