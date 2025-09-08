'use strict';

const assert = require('assert');
const { MockConfigClient } = require('./_helper');

const url = new URL('http://un:pw@axwaylocal.com');
const events = {
	'com.test.event': null,
	'com.test.topic.*': null,
	'com.test.*.interior': null,
	'com.splatted.**': null
};
const topics = Object.keys(events);
const pubsub = new MockConfigClient({
	url: 'url',
	key: 'key',
	secret: 'secret',
	config: {
		url: url.href,
		can_consume: true,
		auth_type: 'basic',
		auth_user: url.username,
		auth_pass: url.password,
		events,
		topics
	}
});

describe('validation', function () {

	it('should validate exact event name matches', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.event'), true);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.event', topics), true);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.topic.*'), true);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.topic.*', topics), true);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.*.interior'), true);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.*.interior', topics), true);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.splatted.**'), true);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.splatted.**', topics), true);
	});

	it('should not validate events matching wildcard terminus segment', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.topic.anything'), false);
	});

	it('should not validate events matching wildcard interior segment', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.anything.interior'), false);
	});

	it('should not validate events matching double-splatted topic', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.splatted.shortName'), false);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.splatted.a.much.longer.event.name', topics), false);
	});

	it('should not validate unsubscribed event topics', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.invalid.event'), false);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.invalid.event', topics), false);
	});

	it('should not validate descendant topics', function () {
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.event.descendant'), false);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.topic.wildcard.descendant'), false);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.wildcard.interior.descendant'), false);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.event.descendant', topics), false);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.topic.wildcard.descendant', topics), false);
		assert.strictEqual(pubsub.hasSubscribedTopic('com.test.wildcard.interior.descendant', topics), false);
	});
});
