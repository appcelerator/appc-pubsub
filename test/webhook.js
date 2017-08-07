const assert = require('assert');
const crypto = require('crypto');
const PubSub = require('../');

// Valid client details should be used
let key = '',
	secret = '',
	pubsub;

/**
 * Mock response object to capture response details.
 */
function Response() {
}
Response.prototype.writeHead = function (code, headers) {
	this.code = code;
	this.headers = headers;
};
Response.prototype.write = function (str) {
	this.body = str;
};
Response.prototype.end = function () {
	this.ended = true;
};
Response.prototype.wasUnauthorized = function () {
	return this.code === 401 && this.ended;
};

/**
 * Mock request object
 * @param {Object} body the request body
 * @param {Object} headers the request headers
 */
function Request(body, headers) {
	this.headers = headers || {};
	this.body = body || {};
}

describe('webhook', function () {

	// Create a new client and wait for the config to be fetched
	before('new client', function (next) {
		pubsub = new PubSub({
			key: key,
			secret: secret
		});
		pubsub.on('configured', () => next());
	});

	it('should validate basic auth credentials', function () {
		// Set the config and parse the basic auth details
		pubsub._parseConfig(Object.assign(pubsub.config, {
			auth_type: 'basic',
			url: 'http://un:pw@localhost:8080.com'
		}));
		let success = false,
			res = new Response(),
			req = new Request({}, {
				authorization: 'Basic ' + new Buffer('un:pw').toString('base64')
			});

		// Test the return value and that the callback is called for middleware use
		let authed = pubsub.authenticateWebhook(req, res, () => success = true);
		// Both should have succeeded
		assert.ok(success && authed);

		// Make sure incorrect credentials are handled
		req.headers.authorization = 'Basic ' + new Buffer('un2:pw2').toString('base64');
		success = false;
		authed = pubsub.authenticateWebhook(req, res, () => success = true);
		// The return value should be false and the callback should not have been called
		assert.equal(success || authed, false);
		// If a response object is given then an unauthorized response should be sent
		assert.ok(res.wasUnauthorized());
	});

	it('should validate auth token', function () {
		// Set the config and parse the basic auth details
		pubsub._parseConfig(Object.assign(pubsub.config, {
			auth_type: 'token',
			url: 'http://localhost:8080.com',
			auth_token: 'test-token'
		}));
		let success = false,
			res = new Response(),
			req = new Request({}, {
				'x-auth-token': 'test-token'
			});

		// Correct creds
		let authed = pubsub.authenticateWebhook(req, res, () => success = true);
		assert.ok(success && authed);

		// Incorrect creds
		req.headers['x-auth-token'] = 'not-this';
		success = false;
		authed = pubsub.authenticateWebhook(req, res, () => success = true);
		assert.equal(success || authed, false);
		assert.ok(res.wasUnauthorized());
	});

	it('should validate key/secret signature', function () {
		// set the config and parse the basic auth details
		pubsub._parseConfig(Object.assign(pubsub.config, {
			auth_type: 'key_secret',
			url: 'http://localhost:8080.com',
			auth_token: 'test-token'
		}));
		let success = false,
			res = new Response(),
			body = { event: 'com.test.event' },
			req = new Request(body, {
				'x-signature': crypto.createHmac('SHA256', pubsub.secret).update(JSON.stringify(body)).digest('hex')
			});

		// Correct creds
		let authed = pubsub.authenticateWebhook(req, res, () => success = true);
		assert.ok(success && authed);

		// Incorrect creds
		req.headers['x-signature'] = 'not-this';
		success = false;
		authed = pubsub.authenticateWebhook(req, res, () => success = true);
		assert.equal(success || authed, false);
		assert.ok(res.wasUnauthorized());
	});

	it('should emit using an exact event name', function (next) {
		let event = 'com.test.event',
			payload = { event };

		// Set the listener
		pubsub.on(event, function (data) {
			// The request body should be passed through
			assert.equal(data, payload);
			next();
		});
		// Spoof an webhook request skipping authentication
		pubsub.config.auth_type = null;
		pubsub.handleWebhook(new Request(payload), new Response());
	});

	it('should emit using a regex topic', function (next) {
		let reEvent = 'com.test.topic.*',
			event = 'com.test.topic.regex',
			payload = { event };

		// The regex topic needs to be in the clients configured topics
		pubsub.config.topics.push(reEvent);
		pubsub.on(reEvent, function (data) {
			assert.equal(data, payload);
			next();
		});
		pubsub.handleWebhook(new Request(payload), new Response());
	});

	it('should not receive an unrelated event', function () {
		let event = 'com.unrelated.event',
			payload = { event };

		// Set the listener
		pubsub.on('com.different.event', function (data) {
			assert.fail('Listener should not have been called');
		});
		pubsub.handleWebhook(new Request(payload), new Response());
	});
});
