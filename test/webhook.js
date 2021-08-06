'use strict';

const assert = require('assert');
const crypto = require('crypto');
const helper = require('./_helper');

// Valid client details should be used
let Request = helper.Request;
let Response = helper.Response;
let pubsub = new helper.createMockConfigClient({
	key: 'key',
	secret: 'secret'
});

pubsub.updateConfig({
	auth_type: 'basic',
	url: 'http://un:pw@axwaylocal.com',
	can_consume: true,
	events: {
		'com.test.event': null,
		'com.test.topic.*': null,
		'com.test.*.interior': null,
		'com.splatted.**': null
	}
});

describe('webhook', function () {

	it('should validate basic auth credentials are correct', function () {
		// Set the config and parse the basic auth details
		let success = false,
			res = new Response(),
			req = new Request({}, {
				authorization: 'Basic ' + Buffer.from('un:pw').toString('base64')
			});

		// Test the return value and that the callback is called for middleware use
		let authed = pubsub.authenticateWebhook(req, res, () => success = true);
		// Both should have succeeded, and the request should be flagged to avoid duplicate checks
		assert.ok(success && authed && req._authenticatedWebhook);
	});

	it('should validate basic auth credentials are incorrect', function () {
		let success = false,
			res = new Response(),
			req = new Request({}, {
				authorization: 'Basic ' + Buffer.from('un2:pw2').toString('base64')
			});

		let authed = pubsub.authenticateWebhook(req, res, () => success = true);
		// The return value should be false and the callback should not have been called
		assert.strictEqual(success || authed || !!req._authenticatedWebhook, false);
		// If a response object is given then an unauthorized response should be sent
		assert.ok(res.wasUnauthorized());
	});

	it('should validate auth token are correct', function () {
		// Set the config and parse the basic auth details
		pubsub.updateConfig({
			auth_type: 'token',
			url: 'http://axwaylocal.com',
			auth_token: 'test-token'
		});
		let success = false,
			res = new Response(),
			req = new Request({}, {
				'x-auth-token': 'test-token'
			});

		// Correct creds
		let authed = pubsub.authenticateWebhook(req, res, () => success = true);
		assert.ok(success && authed && req._authenticatedWebhook);
	});

	it('should validate auth token are incorrect', function () {
		// Incorrect creds
		let success = false,
			res = new Response(),
			req = new Request({}, {
				'x-auth-token': 'not-this'
			});

		let authed = pubsub.authenticateWebhook(req, res, () => success = true);
		assert.strictEqual(success || authed || !!req._authenticatedWebhook, false);
		assert.ok(res.wasUnauthorized());
	});

	it('should validate key/secret signature is correct', function () {
		// set the config and parse the basic auth details
		pubsub.updateConfig({
			auth_type: 'key_secret',
			url: 'http://axwaylocal.com',
			auth_token: 'test-token'
		});
		let success = false,
			res = new Response(),
			body = { event: 'com.test.event' },
			req = new Request(body, {
				'x-signature': crypto.createHmac('SHA256', pubsub.secret).update(JSON.stringify(body)).digest('hex')
			});

		// Correct creds
		let authed = pubsub.authenticateWebhook(req, res, () => success = true);
		assert.ok(success && authed && req._authenticatedWebhook);
	});

	it('should validate key/secret signature is incorrect', function () {
		// Incorrect creds
		let success = false,
			res = new Response(),
			req = new Request({}, {
				'x-signature': 'not-this'
			});

		let authed = pubsub.authenticateWebhook(req, res, () => success = true);
		assert.strictEqual(success || authed || !!req._authenticatedWebhook, false);
		assert.ok(res.wasUnauthorized());
	});

	it('should emit using an exact event name', function (done) {
		let topic = pubsub.config.topics[0],
			payload = { topic };

		// Set the listener
		pubsub.on('event:' + topic, function (data) {
			// The request body should be passed through
			assert.strictEqual(data, payload);
			done();
		});
		// Spoof an webhook request skipping authentication
		pubsub.config.auth_type = null;
		pubsub.handleWebhook(new Request(payload), new Response());
	});

	it('should not receive an unrelated event', function () {
		let topic = 'com.unrelated.event',
			payload = { topic };

		// Set the listener
		pubsub.on('event:com.different.event', function () {
			assert.fail('Listener should not have been called');
		});
		pubsub.handleWebhook(new Request(payload), new Response());
	});
});
