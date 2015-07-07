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
		process.env.NODE_ENV === ' preproduction' ||
		process.env.APPC_ENV === 'preproduction' ||
		process.env.NODE_ENV === 'development' ||
		process.env.APPC_ENV === 'development';
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
}

util.inherits(PubSubClient, EventEmitter);

/**
 * publish an event with name and optional data
 * @param {String} name name of the event
 * @param {Object} data optional event payload or undefined/null if no event data
 */
PubSubClient.prototype.publish = function (name, data) {
	if (!name) {
		throw new Error('required event name');
	}
	if (data && typeof(data)!=='object') {
		throw new Error('data must be an object');
	}
	var event = {
			event: name,
			data: data
		},
		opts = {
			url: url.resolve(this.url, '/api/event'),
			method: 'post',
			json: event,
			headers: {
				'User-Agent': 'Appcelerator PubSub Client/' + version,
				'APIKey': this.key,
				'APISig': crypto.createHmac('SHA256',this.secret).update(JSON.stringify(event)).digest('base64')
			},
			gzip: true,
			timeout: this.timeout,
			followAllRedirects: true,
			rejectUnauthorized: this.url.indexOf('360-local') < 0
		};
	this.queue.push(opts);
	// if we don't have a timer scheduled, run one near immediately
	if (!this.timer) {
		this.timer = setTimeout(this._runQueue.bind(this), 10);
	}
};

/**
 * internal method to requeue an event
 */
PubSubClient.prototype._requeue = function (reason, opts) {
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
	// reset the timer
	this.timer = null;
	this.retry = (this.retry || 0) + 1;
	// pop off the pending event in the queue FIFO
	var opts = this.queue.shift(),
		self = this,
		handler = createErrorHandler(this, opts);

	try {
		var req = request(opts);
		// handle response
		req.on('response',function (resp) {
			if (resp && resp.statusCode!==200) {
				// an error which isn't a security error, try to push again
				if (resp && resp.statusCode && !/^(400|401)$/.test(resp.statusCode)) {
					return self._requeue(resp.statusCode, opts);
				}
				var err = new Error('invalid response');
				err.code = resp.statusCode;
				self.emit('error', err, opts);
				debug('error', err);
			} else {
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
};

module.exports = PubSubClient;
