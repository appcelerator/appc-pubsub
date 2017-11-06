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
		assert.equal(pubsub.getSubscribedTopic('com.test.event'), 'com.test.event');
	});

	it('should validate events matching wildcard terminus segment', function () {
		assert.equal(pubsub.getSubscribedTopic('com.test.topic.anything'), 'com.test.topic.*');
	});

	it('should validate events matching wildcard interior segment', function () {
		assert.equal(pubsub.getSubscribedTopic('com.test.anything.interior'), 'com.test.*.interior');
	});

	it('should validate events matching double-splatted topic', function () {
		assert.equal(pubsub.getSubscribedTopic('com.splatted.shortName'), 'com.splatted.**');
		assert.equal(pubsub.getSubscribedTopic('com.splatted.a.much.longer.event.name'), 'com.splatted.**');
	});

	it('should not validate unsubscribed event topics', function () {
		assert.equal(pubsub.getSubscribedTopic('com.invalid.event'), null);
	});

	it('should not validate descendant topics', function () {
		assert.equal(pubsub.getSubscribedTopic('com.test.event.descendant'), null);
		assert.equal(pubsub.getSubscribedTopic('com.test.topic.wildcard.descendant'), null);
		assert.equal(pubsub.getSubscribedTopic('com.test.wildcard.interior.descendant'), null);
	});
});
