const { createHash, createHmac } = require('crypto');
const { EventEmitter } = require('events');
const { hostname } = require('os');

const auth = require('basic-auth');
const debug = require('debug');

const { version } = require('../package.json');

const fingerprint = createHash('sha256').update(hostname() || Date.now()).digest('hex');

const DEFAULT = {
	timeout: 10000,
	retryLimit: 10,
	reconfigureTimeout: null,
	headers: {
		'content-type': 'application/json',
		'user-agent': `pubsub-client/${version} (${fingerprint})`
	}
};

const logger = {
	info: debug('pubsub-client:info'),
	error: debug('pubsub-client:error')
};

class PubSubClient extends EventEmitter {
	// PubSub Server options
	#url;
	#key;
	#secret;

	// Communication options
	#timeout;
	#retryLimit;
	#retries = {};

	// Client config
	_config = null;

	// Queue to hold pending topic checks while initial configuration is in progress
	#pendingChecks = [];

	constructor(opts) {
		super();

		opts = opts || {};

		// Enable logging if enabled.
		opts.debug && debug.enable('pubsub-client:' + (typeof opts.debug === 'string' ? opts.debug : '*'));

		if (!opts.url) {
			throw new Error('Missing required option: url');
		}
		try {
			new URL(opts.url);
		} catch (_e) {
			throw new Error('Invalid URL format');
		}

		if (!opts.key || typeof opts.key !== 'string') {
			throw new Error('Missing required option: key');
		}

		if (!opts.secret || typeof opts.secret !== 'string') {
			throw new Error('Missing required option: secret');
		}

		this.#url = opts.url;
		this.#key = opts.key;
		this.#secret = opts.secret;

		this.#timeout = Number(opts.timeout) || DEFAULT.timeout;
		this.#retryLimit = Number(opts.retryLimit) || DEFAULT.retryLimit;

		const reconfigureTimeout = Number(opts.reconfigureTimeout) || DEFAULT.reconfigureTimeout;
		if (reconfigureTimeout) {
			logger.info('Client reconfiguration enabled', this.#key, reconfigureTimeout);
			setInterval(() => this._fetchConfig(), reconfigureTimeout);
		}

		this._fetchConfig();
	}

	/**
	 * Check if the client is configured to receive a specific topic
	 * @param {String} topic topic to check
	 * @returns {Boolean} true if this client is configured to receive the topic
	 */
	hasSubscribedTopic(topic) {
		return this._config?.topics.includes(topic);
	}

	/**
	 * Subscribe to a topic. Logging if the client is not configured to receive it
	 * @param {String} name topic to subscribe to
	 * @param {*} fn callback to be called when the topic is published
	 * @returns {EventEmitter} event emitter instance
	 */
	on(name, fn) {
		logger.info('on', name);
		if (!this._config) {
			// If not yet configured - remember the topic to check later
			this.#pendingChecks.push(name);
		} else {
			this.#validateTopic(name);
		}
		return super.on(name, fn);
	}

	/**
	 * Middleware to authenticate incoming webhook request
	 * @param {*} req request
	 * @param {*} res response
	 * @param {*} next next middleware
	 * @returns {Promise<boolean>} whether the authentication was successful
	 */
	async authenticateWebhook(req, res, next) {
		if (req._authenticatedWebhook) {
			next && next();
			return true;
		}

		const body = await this.#parseBody(req, res);
		if (!body) {
			return false;
		}

		// Make sure the client has consumption enabled
		if (!this._config.can_consume) {
			this.#webhookResponse(res, 400, {
				success: false,
				message: 'This client does not have consumption enabled.'
			});

			return false;
		}
		logger.info('authenticating webhook using: method =', this._config.auth_type);

		const conf = this._config;
		const headers = req && req.headers || {};
		const creds = auth(req);
		// Validate request using clients authentication method
		// Check the basic auth credentials match...
		const authenticated = conf.auth_type === 'basic' ? creds.name === conf.auth_user && creds.pass === conf.auth_pass
			// ...or the request has the correct auth token
			: conf.auth_type === 'token' ? headers['x-auth-token'] === conf.auth_token
				// ...or the signature matches the body signed with the client secret
				: conf.auth_type === 'key_secret' ? headers['x-signature'] === createHmac('SHA256', this.#secret).update(JSON.stringify(body)).digest('hex')
					// ...otherwise there's no authentication for the client
					: true;

		// Make sure the request is from pubsub server
		if (!authenticated) {
			logger.error('webhook authentication failed', headers);

			this.#webhookResponse(res, 401, {
				success: false,
				message: 'Unauthorized.'
			});

			return false;
		}
		req._authenticatedWebhook = true;
		next && next();
		return true;
	}

	/**
	 * Middleware to handle incoming webhook calls
	 * @param {*} req request
	 * @param {*} res response
	 * @returns {Promise<void>}
	 */
	async handleWebhook(req, res) {
		if (!await this.authenticateWebhook(req, res)) {
			return;
		}

		const body = await this.#parseBody(req, res);
		if (!body) {
			return;
		}

		logger.info(`Event received: ${body.topic}`);

		if (this.hasSubscribedTopic(body.topic)) {
			this.emit(`event:${body.topic}`, body);
		}

		// Confirm receipt to the webhook request
		this.#webhookResponse(res, 200, { success: true });
	}

	/**
	 * Publish event to PubSub server
	 * @param {String} event event name
	 * @param {Object} data event data
	 * @param {Object} options event options
	 * @returns {*}
	 */
	async publish(event, data = {}, options = {}) {
		logger.info('publish', event);
		if (!event) {
			throw new Error('required event name');
		}
		if (Buffer.byteLength(event) > 255) {
			throw new Error('name length must be less than 255 bytes');
		}
		if (typeof data !== 'object' || Array.isArray(data)) {
			throw new Error('data must be an object');
		}
		if (typeof options !== 'object' || Array.isArray(options)) {
			throw new Error('options must be an object');
		}

		// Clone data before serialization pass so objects are not modified.
		try {
			data = this.#sanitize(JSON.parse(JSON.stringify(data)));
		} catch (_e) {
			throw new Error('data could not be parsed');
		}

		// Default timestamp if not provided.
		if (!options.timestamp) {
			options.timestamp = Date.now();
		}

		// Generate identifier and send event.
		await this._send(event + '-' + Date.now(), { data, event, options });
	}

	/**
	 * Modifies published event
	 * @param {String} id event identifier
	 * @param {Object} data event data
	 * @param {Object} options event options
	 * @returns {*}
	 */
	async update(id, data = {}, options = {}) {
		logger.info('patch', id);
		if (!id) {
			throw new Error('required event id');
		}
		if (typeof data !== 'object' || Array.isArray(data)) {
			throw new Error('data must be an object');
		}
		if (typeof options !== 'object' || Array.isArray(options)) {
			throw new Error('options must be an object');
		}

		// Clone data before serialization pass so objects are not modified.
		try {
			data = this.#sanitize(JSON.parse(JSON.stringify(data || {})));
		} catch (_e) {
			throw new Error('data could not be parsed');
		}

		// Generate identifier and send event.
		await this._send(id + '-' + Date.now(), { id, data, options });
	}

	/**
	 * Send event to the PubSub server
	 * @param {String} id event identifier
	 * @param {Object} data event data
	 * @returns {*}
	 */
	async _send(id, data) {
		logger.info('send', id, data);

		// Fall out if no event or id set.
		if (!data?.event && !data?.id) {
			return;
		}

		this.#retries[id] = (this.#retries[id] || 0) + 1;

		const url = new URL('/api/event', this.#url);
		const body = JSON.stringify(data);
		const opts = {
			url: url.href,
			method: 'POST',
			headers: this.#makeHeaders(body),
			body,
			signal: AbortSignal.timeout(this.#timeout)
		};

		if (data.id) {
			opts.url += `/${data.id}`;
			opts.method = 'PATCH';
		}

		try {
			const resp = await fetch(opts.url, opts);
			if (resp.ok) {
				delete this.#retries[id];
				// emit an event
				this.emit('response', resp, opts);

				logger.info('response received, status:', resp.status);
				return;
			}

			const err = new Error('invalid response');
			err.code = resp.status;

			// if 401, that means the apikey or secret is wrong or event is not allowed; do not attempt to retry
			// if 403, that means patch is called with wrong client
			if (err.code === 401 || err.code === 403) {
				err.message = 'Unauthorized';
				this.emit('unauthorized', String(err), opts);
				return logger.error('sending event failed', String(err));
			}

			// if 404, that means the id given for PATCH event is not found
			if (err.code === 404) {
				err.message = 'NotFound';
				this.emit('notfound', String(err), opts);
				return logger.error('updating event failed', String(err));
			}

			// if 400, that means the event failed validation; do not attempt to retry
			if (err.code === 400) {
				err.message = 'Failed';
				return logger.error('sending event failed', await resp.text());
			}

			// Otherwise, since it wasn't a validation or authorization error, log and retry.
			logger.error('received error', String(err), opts);

			// run again with exponential backoff each time
			const retryAfter = Math.max(500, (Math.pow(2, this.#retries[id]) - 1) * 500);

			if (this.#retries[id] > this.#retryLimit) {
				logger.error('Retry limit exceeded', new Error().stack);
			} else {
				logger.info(`Retry scheduled after ${retryAfter}ms`, err.code, opts);
				setTimeout(() => this._send(id, data), retryAfter);
				this.emit('retry', err.code, opts, this.#retries[id]);
			}
		} catch (e) {
			// axios throwing outright (and not getting caught) likely means invalid opts.
			// Log, but do not retry.
			logger.error('web request received error', e, opts);
		}
	}

	/**
	 * Initiate fetch of this client's configuration from PubSub server
	 * Sets the fetched configuration in this._config and fires 'configured'
	 */
	async _fetchConfig() {
		logger.info('Fetching client config', this.#key);

		const response = await fetch(new URL('/api/config', this.#url), {
			headers: this.#makeHeaders('{}'),
			signal: AbortSignal.timeout(this.#timeout),
		});

		if (!response.ok) {
			const message = `Failed to fetch config: ${await response.text()}`;
			logger.error(message);
			throw new Error(message);
		}

		const body = await response.json();
		const config = body && body.key && body[body.key];
		if (!config) {
			const message = `Bad config format: ${body}`;
			logger.error(message);
			throw new Error(message);
		}

		if (config.can_consume) {
			config.topics = Object.keys(config.events || {});
			if (config.auth_type === 'basic' && config.url) {
				const url = new URL(config.url);
				config.auth_user = url.username;
				config.auth_pass = url.password;
			}
		}

		this._config = config;

		// Do pending topic validation
		this.#pendingChecks.forEach(topic => this.#validateTopic(topic));
		this.#pendingChecks = [];

		this.emit('configured', this._config);

		logger.info('Client configured', this.#key);
	}

	#makeHeaders(body) {
		return {
			...DEFAULT.headers,
			APIKey: this.#key,
			APISig: createHmac('SHA256', this.#secret).update(body).digest('base64')
		};
	}

	#parseBody(req, res) {
		// If the body is already parsed return it.
		if (req.body || req._pubsubBody) {
			return req.body || req._pubsubBody;
		}

		// Expect JSON body.
		if (req.headers['content-type'] !== 'application/json') {
			this.#sendBodyParseError(req, res);
			return Promise.reject();
		}

		const length = req.headers['content-length'];
		let data = '';

		return new Promise((resolve, reject) => {
			// Read the request body falling out if it's too long.
			req.on('data', req._pubsubDataListener = (chunk) => {
				data += chunk.toString();
				if (data.length > length) {
					this.#sendBodyParseError(req, res);
					return reject(new Error('Body too large'));
				}
			});

			// Once the request has ended parse the body.
			req.on('end', req._pubsubEndListener = () => {
				let parsed;
				try {
					parsed = JSON.parse(data);
				} catch (_err) {
					this.#sendBodyParseError(req, res);
					return reject(new Error('Invalid JSON'));
				}
				req._pubsubBody = parsed;
				resolve(parsed);
			});
		});
	}

	#sendBodyParseError(req, res) {
		// Terminate event listeners
		req._pubsubDataListener && req.off('data', req._pubsubDataListener);
		req._pubsubEndListener && req.off('end', req._pubsubEndListener);

		// Respond with error
		this.#webhookResponse(res, 400, { success: false, message: 'Body parse error' });
	}

	#webhookResponse(res, code, body) {
		if (!res) {
			return;
		}

		res.writeHead(code, { 'content-type': 'application/json' });
		res.end(JSON.stringify(body));
	}

	#sanitize(obj, seen = []) {
		if (!obj || typeof obj !== 'object') {
			return obj;
		}
		if (obj instanceof RegExp) {
			return obj.source;
		}
		if (obj instanceof Date) {
			return obj;
		}
		Object.keys(obj).forEach(key => {
			let value = obj[key];
			const type = typeof value;
			if (type === 'function') {
				delete obj[key];
			} else if (/^(password|creditcard)/.test(key)) {
				// the server side does masking as well, but doesn't hurt to do it at origin
				obj[key] = '[HIDDEN]';
			} else if (value instanceof Date) {
				// do nothing
			} else if (value instanceof RegExp) {
				obj[key] = value.source;
			} else if (value && type === 'object') {
				if (seen.includes(value)) {
					value = '[Circular]';
				} else {
					seen.push(value);
					value = this.#sanitize(value, seen);
				}
				obj[key] = value;
			}
		});
		return obj;
	}

	/**
	 * Validate if the given event subscription topic is in the client's configured topics
	 * @param {String} topic topic to check (only interested in 'event:XXX')
	 */
	#validateTopic(topic) {
		// Only interested in validating event subscriptions
		if (!String(topic).startsWith('event:')) {
			return;
		}

		// String `event:` prefix
		topic = topic.replace('event:', '');

		if (!this.hasSubscribedTopic(topic)) {
			logger.error(`Unexpected event '${topic}': client not configured to receive this event.`);
		}
	}
}

module.exports = PubSubClient;
