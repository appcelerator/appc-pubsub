'use strict';

const assert = require('assert');
const crypto = require('crypto');
const { MockConfigClient, MockRequest: Request, MockResponse: Response } = require('./_helper');

// Valid client details should be used
const url = new URL('http://un:pw@axwaylocal.com');
const events = {
	'com.test.event': null,
	'com.test.topic.*': null,
	'com.test.*.interior': null,
	'com.splatted.**': null
};
const config = {
	url: 'url',
	key: 'key',
	secret: 'secret',
	config: {
		url: url.href,
		can_consume: true,
		auth_type: 'basic',
		auth_user: url.username,
		auth_pass: url.password,
		topics: Object.keys(events)
	}
};
const pubsub = new MockConfigClient(config);

describe('webhook', function () {

	it('should validate basic auth credentials are correct', async function () {
		// Set the config and parse the basic auth details
		let success = false,
			res = new Response(),
			req = new Request({}, {
				authorization: 'Basic ' + Buffer.from('un:pw').toString('base64')
			});

		// Test the return value and that the callback is called for middleware use
		let authed = await pubsub.authenticateWebhook(req, res, () => success = true);
		// Both should have succeeded, and the request should be flagged to avoid duplicate checks
		assert.ok(success && authed && req._authenticatedWebhook);
	});

	it('should validate basic auth credentials are incorrect', async function () {
		let success = false,
			res = new Response(),
			req = new Request({}, {
				authorization: 'Basic ' + Buffer.from('un2:pw2').toString('base64')
			});

		let authed = await pubsub.authenticateWebhook(req, res, () => success = true);
		// The return value should be false and the callback should not have been called
		assert.strictEqual(success || authed || !!req._authenticatedWebhook, false);
		// If a response object is given then an unauthorized response should be sent
		assert.ok(res.wasUnauthorized());
	});

	it('should validate auth token are correct', async function () {
		// Change config to auth token.
		pubsub._config.auth_type = 'token';
		pubsub._config.url = 'http://axwaylocal.com';
		pubsub._config.auth_token = 'test-token';
		delete pubsub._config.auth_user;
		delete pubsub._config.auth_pass;
		let success = false,
			res = new Response(),
			req = new Request({}, {
				'x-auth-token': 'test-token'
			});

		// Correct creds
		let authed = await pubsub.authenticateWebhook(req, res, () => success = true);
		assert.ok(success && authed && req._authenticatedWebhook);
	});

	it('should validate auth token are incorrect', async function () {
		// Incorrect creds
		let success = false,
			res = new Response(),
			req = new Request({}, {
				'x-auth-token': 'not-this'
			});

		let authed = await pubsub.authenticateWebhook(req, res, () => success = true);
		assert.strictEqual(success || authed || !!req._authenticatedWebhook, false);
		assert.ok(res.wasUnauthorized());
	});

	it('should validate key/secret signature is correct', async function () {
		// Change config to key/secret.
		pubsub._config.auth_type = 'key_secret';
		delete pubsub._config.auth_token;

		let success = false,
			res = new Response(),
			body = { event: 'com.test.event' },
			req = new Request(body, {
				'x-signature': crypto.createHmac('SHA256', config.secret).update(JSON.stringify(body)).digest('hex')
			});

		// Correct creds
		let authed = await pubsub.authenticateWebhook(req, res, () => success = true);
		assert.ok(success && authed && req._authenticatedWebhook);
	});

	it('should validate key/secret signature is incorrect', async function () {
		// Incorrect creds
		let success = false,
			res = new Response(),
			req = new Request({}, {
				'x-signature': 'not-this'
			});

		let authed = await pubsub.authenticateWebhook(req, res, () => success = true);
		assert.strictEqual(success || authed || !!req._authenticatedWebhook, false);
		assert.ok(res.wasUnauthorized());
	});

	it('should parse the body when not already set', async function () {
		// Change config to key/secret.
		pubsub._config.auth_type = 'key_secret';
		delete pubsub._config.auth_token;

		let success = false,
			res = new Response(),
			bodyParts = [ '{"event":', '"com.test.body"', '}' ],
			bodyString = bodyParts.join(''),
			req = new Request(null, {
				'x-signature': crypto.createHmac('SHA256', config.secret).update(bodyString).digest('hex'),
				'content-length': bodyString.length,
				'content-type': 'application/json'
			});

		// Emit body
		let auth = pubsub.authenticateWebhook(req, res, () => success = true);
		bodyParts.forEach(part => req.emit('data', Buffer.from(part, 'utf8')));
		req.emit('end');
		let authed = await auth;
		assert.ok(success && authed && req._authenticatedWebhook);
	});

	it('should emit using an exact event name', function (done) {
		let topic = pubsub._config.topics[0],
			payload = { topic };

		// Set the listener
		pubsub.on('event:' + topic, function (data) {
			// The request body should be passed through
			assert.strictEqual(data, payload);
			done();
		});
		// Spoof a webhook request skipping authentication
		pubsub._config.auth_type = null;
		pubsub.handleWebhook(new Request(payload), new Response());
	});

	it('should not receive an unrelated event', async function () {
		let topic = 'com.unrelated.event',
			payload = { topic };

		// Set the listener
		pubsub.on('event:com.different.event', function () {
			assert.fail('Listener should not have been called');
		});
		pubsub.handleWebhook(new Request(payload), new Response());
	});
});
