'use strict';

const assert = require('assert');
const helper = require('./_helper');

// Valid client details should be used
let pubsub = new helper.createMockConfigClient({
	key: 'key',
	secret: 'secret'
});

let events = {
	'com.test.event': null,
	'com.test.topic.*': null,
	'com.test.*.interior': null,
	'com.splatted.**': null
};
let topics = Object.keys(events);

const url = new URL('http://un:pw@axwaylocal.com');
pubsub.config = {
	url: url.href,
	can_consume: true,
	auth_type: 'basic',
	auth_user: url.username,
	auth_pass: url.password,
	events,
	topics
};

describe('validation', function () {

	it('should validate exact event name matches', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.event'), 'com.test.event');
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.event', topics), 'com.test.event');
	});

	it('should validate events matching wildcard terminus segment', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.topic.anything'), 'com.test.topic.*');
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.topic.anything', topics), 'com.test.topic.*');
	});

	it('should validate events matching wildcard interior segment', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.anything.interior'), 'com.test.*.interior');
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.anything.interior', topics), 'com.test.*.interior');
	});

	it('should validate events matching double-splatted topic', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.splatted.shortName'), 'com.splatted.**');
		assert.strictEqual(pubsub.hasSubscribedTopic('com.splatted.a.much.longer.event.name'), 'com.splatted.**');
		assert.strictEqual(pubsub.hasSubscribedTopic('com.splatted.shortName', topics), 'com.splatted.**');
		assert.strictEqual(pubsub.hasSubscribedTopic('com.splatted.a.much.longer.event.name', topics), 'com.splatted.**');
	});

	it('should not validate unsubscribed event topics', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.invalid.event'), null);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.invalid.event', topics), null);
	});

	it('should not validate descendant topics', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.event.descendant'), null);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.topic.wildcard.descendant'), null);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.wildcard.interior.descendant'), null);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.event.descendant', topics), null);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.topic.wildcard.descendant', topics), null);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.wildcard.interior.descendant', topics), null);
	});
});
