const { createHash, createHmac } = require('crypto');
const { EventEmitter } = require('events');
const { hostname } = require('os');
const { inherits } = require('util');

const axios = require('axios');
const auth = require('basic-auth');
const debugModule = require('debug');

const { version } = require('../package.json');

const environments = {
	production: 'https://pubsub.platform.axway.com',
	preproduction: 'https://pubsub.axwaytest.net'
};
const fingerprint = createHash('sha256').update(hostname() || Date.now()).digest('hex');
const preproductionEnvironments = [ 'preproduction', 'development' ];
const userAgent = `appc-pubsub/${version} (${fingerprint})`;

const pendingChecks = [];
const debug = {
	info: debugModule('appc-pubsub:info'),
	error: debugModule('appc-pubsub:error')
};

/**
 * Class constructor
 *
 * @class PubSubClient
 * @param {Object} opts options for configuring the client
 */
function PubSubClient(opts) {
	opts = opts || {};

	// Enable logging if enabled.
	opts.debug && debugModule.enable('appc-pubsub:' + (typeof opts.debug === 'string' ? opts.debug : '*'));

	// prefer the environment settings over config
	const env = opts.env || (_isPreproduction() ? 'preproduction' : 'production');
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
	this.retryLimit = opts.retryLimit || 10;
	this.retries = {};

	this.fetchConfig();

	// These functions need the client binding for use as a middleware/route
	this.authenticateWebhook = this.authenticateWebhook.bind(this);
	this.handleWebhook = this.handleWebhook.bind(this);
}

inherits(PubSubClient, EventEmitter);

/**
 * Authenticates a webhook request as being from pubsub server. Can be used as middleware.
 * @param {http.ClientRequest} req request object containing auth details
 * @param {http.ServerResponse} [res] response object for responding with errors
 * @param {Function} [next] optional callback function for use in middleware
 * @return {Boolean} whether the request is authenticated
 */
PubSubClient.prototype.authenticateWebhook = async function (req, res, next) {
	if (req._authenticatedWebhook) {
		next && next();
		return true;
	}

	const body = await this._getBody(req, res);
	if (!body) {
		return false;
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
	debug.info('authenticating webhook using: method =', this.config.auth_type);

	const conf = this.config;
	const headers = req && req.headers || {};
	const creds = auth(req);
	// Validate request using clients authentication method
	// Check the basic auth credentials match...
	const authenticated = conf.auth_type === 'basic' ? creds.name === conf.auth_user && creds.pass === conf.auth_pass
		// ...or the request has the correct auth token
		: conf.auth_type === 'token' ? headers['x-auth-token'] === this.config.auth_token
			// ...or the signature matches the body signed with the client secret
			: conf.auth_type === 'key_secret' ? headers['x-signature'] === createHmac('SHA256', this.secret).update(JSON.stringify(body)).digest('hex')
				// ...otherwise there's no authentication for the client
				: true;

	// Make sure the request is from pubsub server
	if (!authenticated) {
		debug.error('webhook authentication failed', headers);
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
 * Fetch client config from the server.
 */
PubSubClient.prototype.fetchConfig = function () {
	const url = new URL('/api/client/config', this.url);
	const opts = {
		url: url.href,
		headers: {
			'user-agent': userAgent,
			APIKey: this.key,
			APISig: createHmac('SHA256', this.secret).update('{}').digest('base64')
		},
		timeout: this.timeout
	};
	debug.info('fetching client config', this.key);
	this.config = {};
	axios(opts)
		.then(resp => {
			const data = resp.data && resp.data.key && resp.data[resp.data.key];
			if (!data) {
				const err = new Error('invalid response');
				return debug.error('error', err, resp.status, resp.data);
			}

			if (data.can_consume) {
				// Extract topic from keys of event map.
				data.topics = Object.keys(data.events || {});

				// Get basic auth creds from the url
				if (data.auth_type === 'basic' && data.url) {
					const url = new URL(data.url);
					data.auth_user = url.username;
					data.auth_pass = url.password;
				}
			}

			this.config = data;

			this.on('configured', () => pendingChecks.forEach(this._validateTopic.bind(this)));
			this.emit('configured', this.config);
			return debug.info('got config', this.config);
		})
		.catch(e => {
			// if 401 that means the apikey, secret is wrong. disable before raising an error
			if (e.response && e.response.status === 401) {
				e.message = 'Unauthorized';
				this.emit('unauthorized', String(e), opts);
			}
			debug.error('error fetching config', String(e));
		});
};

/**
 * Validates that event name is in client's subscribed topics (or provided topic list).
 *
 * @param {String} name topic/event name
 * @param {Array} topics (optional) set of topics to validate against, defaults to this.config.topics
 * @returns {Boolean} true if event matched topics
 */
PubSubClient.prototype.hasSubscribedTopic = function (name, topics) {
	// Event names are prefixed, so strip it.
	name = name.replace('event:', '');
	// Add internal events since they will be emitted.
	const validTopics = [ 'configured', 'unauthorized' ].concat(topics || this.config.topics || []);
	return validTopics.find(topic => {
		// Name matches topic
		if (topic === name) {
			return topic;
		}
		// Fall out if exact match missed and topic does not have wildcard.
		if (!topic.includes('*')) {
			return null;
		}
		const eventSegments = name.split('.');
		const topicSegments = topic.split('.');
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
 * Webhook handler route that exposes events using the EventEmitter pattern.
 * @param {http.ClientRequest} req Request object
 * @param {http.ServerResponse} res Response object
 */
PubSubClient.prototype.handleWebhook = async function (req, res) {
	// Make sure the request has been authenticated
	if (!await this.authenticateWebhook(req, res)) {
		return;
	}

	const body = await this._getBody(req, res);
	if (!body) {
		return;
	}
	const topic = body.topic;
	debug.info('event received', topic, body);

	// Search for any configured regex matches and emit using those too
	if (this.hasSubscribedTopic(topic)) {
		debug.info('emitting event:' + topic);
		this.emit('event:' + topic, body);
	}

	res.writeHead(200, { 'Content-Type': 'application/json' });
	res.end(JSON.stringify({ success: true }));
};

/**
 * Publish an event with name and optional data.
 * @param {String} event name of the event
 * @param {Object} data optional event payload or undefined/null if no event data
 * @param {Object} options the options object
 */
PubSubClient.prototype.publish = function (event, data = {}, options = {}) {
	if (this.disabled) {
		return;
	}
	debug.info('publish', event);
	if (!event) {
		throw new Error('required event name');
	}
	if (Buffer.byteLength(event) > 255) {
		throw new Error('name length must be less than 255 bytes');
	}
	if (typeof data !== 'object' || Array.isArray(data)) {
		throw new Error('data must be an object');
	}
	// Clone data before serialization pass so objects are not modified.
	try {
		data = JSON.parse(JSON.stringify(data || {}));
	} catch (e) {
		throw new Error('data could not be parsed');
	}

	if (typeof options !== 'object' || Array.isArray(data)) {
		throw new Error('options must be an object');
	}

	// Default timestamp if not provided.
	if (!options.timestamp) {
		options.timestamp = Date.now();
	}

	// Generate identifier and send event.
	this._send(event + '-' + Date.now(), {
		data: _sanitize(data, []),
		event,
		options
	});
};

/**
 * Update an event.
 * @param {String} id id of the event
 * @param {Object} data optional event payload or undefined/null if no event data
 * @param {Object} options the options objectq
 */
PubSubClient.prototype.update = function (id, data = {}, options = {}) {
	if (this.disabled) {
		return;
	}
	debug.info('patch', id);
	if (!id) {
		throw new Error('required event id');
	}
	if (typeof data !== 'object' || Array.isArray(data)) {
		throw new Error('data must be an object');
	}
	// Clone data before serialization pass so objects are not modified.
	try {
		data = JSON.parse(JSON.stringify(data || {}));
	} catch (e) {
		throw new Error('data could not be parsed');
	}

	if (typeof options !== 'object' || Array.isArray(data)) {
		throw new Error('options must be an object');
	}

	// Generate identifier and send event.
	this._send(id + '-' + Date.now(), {
		id,
		data: _sanitize(data, []),
		options
	});
};

/**
 * Parse the request body.
 * @param {Object} req Request object
 * @param {Object} res Response object
 * @param {Function} cb Callback function
 * @returns {Promise<Object>} Request body
 */
PubSubClient.prototype._getBody = function (req, res) {
	const self = this;

	// If the body is already parsed return it.
	if (req.body || req._pubsubBody) {
		return req.body || req._pubsubBody;
	}

	// Expect JSON body.
	if (req.headers['content-type'] !== 'application/json') {
		this._sendBodyError(req, res);
		return null;
	}

	const length = req.headers['content-length'];
	let data = '';

	return new Promise(function (resolve) {
		// Read the request body falling out if it's too long.
		req.on('data', req._pubsubDataListener = function (d) {
			data += d.toString();
			if (data.length > length) {
				self._sendBodyError(req, res);
				return resolve(null);
			}
		});

		// Once the request has ended parse the body.
		req.on('end', req._pubsubEndListener = function () {
			let parsed;
			try {
				parsed = JSON.parse(data);
			} catch (err) {
				self._sendBodyError(req, res);
				return resolve(null);
			}
			req._pubsubBody = parsed;
			resolve(parsed);
		});
	});
};

/**
 * Response with an error if the body cannot be parsed.
 * @param {Object} req Request object
 * @param {Object} res Response object
 */
PubSubClient.prototype._sendBodyError = function (req, res) {
	req._pubsubDataListener && req.off('data', req._pubsubDataListener);
	req._pubsubEndListener && req.off('end', req._pubsubEndListener);
	res.writeHead(400, { 'Content-Type': 'application/json' });
	res.end(JSON.stringify({ success: false, message: 'Body parse error' }));
};

/**
 * Retry event.
 * @private
 * @param {String} id hash to identify the event being sent
 * @param {Object} data the data object
 * @param {String} reason the retry reason
 * @param {Object} opts the options object
 * @returns {void}
 */
PubSubClient.prototype._retry = function (id, data, reason, opts) {
	debug.info('retry called', reason, opts);

	if (this.disabled) {
		return debug.info('retry ignored, disabled:', !!this.disabled, new Error().stack);
	}

	if (this.retries[id] > this.retryLimit) {
		return debug.error('Retry limit exceeded', new Error().stack);
	}

	// run again with exponential backoff each time
	setTimeout(() => this._send(id, data), Math.max(500, (Math.pow(2, this.retries[id]) - 1) * 500));
	this.emit('retry', reason, opts, this.retries[id]);
};

/**
 * Sending event to the server.
 * @private
 * @param {String} id hash to identify the event being sent
 * @param {Object} data the data object
 * @return {void}
 */
PubSubClient.prototype._send = function (id, data) {
	if (this.disabled) {
		return false;
	}

	debug.info('_send', id, data);

	// Fall out if no event or id set.
	if (!data?.event && !data?.id) {
		return;
	}

	this.retries[id] = (this.retries[id] || 0) + 1;

	const url = new URL('/api/event', this.url);
	const opts = {
		url: url.href,
		method: 'post',
		data,
		headers: {
			'user-agent': userAgent,
			APIKey: this.key,
			APISig: createHmac('SHA256', this.secret).update(JSON.stringify(data)).digest('base64')
		},
		timeout: this.timeout
	};

	if (data.id) {
		opts.url += `/${data.id}`;
		opts.method = 'patch';
	}

	try {
		axios(opts)
			.then(resp => {
				// reset our retry count on successfully sending
				delete this.retries[id];

				// emit an event
				this.emit('response', resp, opts);

				// log status
				return debug.info('response received, status:', resp.status);
			})
			// handle HTTP errors
			.catch(e => {
				const err = new Error('invalid response');
				err.code = e.response && e.response.status || String(e);

				// if 401, that means the apikey or secret is wrong or event is not allowed; do not attempt to retry
				// if 403, that means patch is called with wrong client
				if (err.code === 401 || err.code === 403) {
					err.message = 'Unauthorized';
					this.emit('unauthorized', String(err), opts);
					return debug.error('sending event failed', String(err));
				}

				// if 404, that means the id given for PATCH event is not found
				if (err.code === 404) {
					err.message = 'NotFound';
					this.emit('notfound', String(err), opts);
					return debug.error('updating event failed', String(err));
				}

				// if 400, that means the event failed validation; do not attempt to retry
				if (err.code === 400) {
					err.message = 'Failed';
					return debug.error('sending event failed', e.response && e.response.data || String(e));
				}

				// Otherwise, since it wasn't a validation or authorization error, log and retry.
				debug.error('received error', String(err), opts);
				return this._retry(id, data, err.code, opts);
			});
	} catch (e) {
		// axios throwing outright (and not getting caught) likely means invalid opts.
		// Log, but do not retry.
		debug.error('web request received error', e, opts);
	}
};

/**
 * Determines if event is a subscribed topic.
 * @private
 * @param {String} name event name
 */
PubSubClient.prototype._validateTopic = function (name) {
	if (String(name).startsWith('event:') && !this.hasSubscribedTopic(name)) {
		debug.error('Unexpected event', name, ': client not configured to receive this event');
	}
};

const on = PubSubClient.prototype.on;
PubSubClient.prototype.on = function (name) {
	debug.info('on', name);
	// If the topics have been fetched then we can attempt to warn about events
	// that aren't configured to be received by this client
	if (!this.configured) {
		pendingChecks.push(name);
	} else {
		this._validateTopic(name);
	}
	return on.apply(this, arguments);
};

module.exports = PubSubClient;

/**
 * Checks process.env flags to determine if env is preproduction or developement.
 * @return {Boolean} flag if preproduction or development env
 */
function _isPreproduction() {
	return String(process.env.NODE_ACS_URL).includes('.appctest.com')
		|| String(process.env.NODE_ACS_URL).includes('.axwaytest.net')
		|| preproductionEnvironments.includes(process.env.NODE_ENV)
		|| preproductionEnvironments.includes(process.env.APPC_ENV);
}

/**
 * Removes potentially private data.
 * @param {Object} obj object to sanitize
 * @param {Array} seen list of enumerated properties
 * @return {Object} sanitized object
 */
function _sanitize(obj, seen) {
	if (!obj || typeof obj !== 'object') {
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
			t = typeof value;
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
				value = _sanitize(value, seen);
			}
			obj[key] = value;
		}
	});
	return obj;
}
