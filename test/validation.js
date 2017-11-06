'use strict';

const assert = require('assert');
const helper = require('./_helper');

// Valid client details should be used
let pubsub = new helper.createMockConfigClient({
	key: 'key',
	secret: 'secret'
});

pubsub.updateConfig({
	url: 'http://un:pw@localhost:8080.com',
	can_consume: true,
	events: {
		'com.test.event': null,
		'com.test.topic.*': null,
		'com.test.*.interior': null,
		'com.splatted.**': null
	}
});

describe('validation', function () {

	it('should validate exact event name matches', function () {
		assert.ok(pubsub.isSubscribedTopic('com.test.event'));
	});

	it('should validate events matching wildcard terminus segment', function () {
		assert.ok(pubsub.isSubscribedTopic('com.test.topic.anything'));
	});

	it('should validate events matching wildcard interior segment', function () {
		assert.ok(pubsub.isSubscribedTopic('com.test.anything.interior'));
	});

	it('should validate events matching double-splatted topic', function () {
		assert.ok(pubsub.isSubscribedTopic('com.splatted.shortName'));
		assert.ok(pubsub.isSubscribedTopic('com.splatted.a.much.longer.event.name'));
	});

	it('should not validate unsubscribed event topics', function () {
		assert.equal(pubsub.isSubscribedTopic('com.invalid.event'), false);
	});

	it('should not validate descendant topics', function () {
		assert.equal(pubsub.isSubscribedTopic('com.test.event.descendant'), false);
		assert.equal(pubsub.isSubscribedTopic('com.test.topic.wildcard.descendant'), false);
		assert.equal(pubsub.isSubscribedTopic('com.test.wildcard.interior.descendant'), false);
	});
});
