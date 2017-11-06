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

pubsub.updateConfig({
	url: 'http://un:pw@localhost:8080.com',
	can_consume: true,
	events
});

describe('validation', function () {

	it('should validate exact event name matches', function () {
		assert.equal(pubsub.getSubscribedTopic('com.test.event'), 'com.test.event');
		assert.equal(pubsub.getSubscribedTopic('com.test.event', topics), 'com.test.event');
	});

	it('should validate events matching wildcard terminus segment', function () {
		assert.equal(pubsub.getSubscribedTopic('com.test.topic.anything'), 'com.test.topic.*');
		assert.equal(pubsub.getSubscribedTopic('com.test.topic.anything', topics), 'com.test.topic.*');
	});

	it('should validate events matching wildcard interior segment', function () {
		assert.equal(pubsub.getSubscribedTopic('com.test.anything.interior'), 'com.test.*.interior');
		assert.equal(pubsub.getSubscribedTopic('com.test.anything.interior', topics), 'com.test.*.interior');
	});

	it('should validate events matching double-splatted topic', function () {
		assert.equal(pubsub.getSubscribedTopic('com.splatted.shortName'), 'com.splatted.**');
		assert.equal(pubsub.getSubscribedTopic('com.splatted.a.much.longer.event.name'), 'com.splatted.**');
		assert.equal(pubsub.getSubscribedTopic('com.splatted.shortName', topics), 'com.splatted.**');
		assert.equal(pubsub.getSubscribedTopic('com.splatted.a.much.longer.event.name', topics), 'com.splatted.**');
	});

	it('should not validate unsubscribed event topics', function () {
		assert.equal(pubsub.getSubscribedTopic('com.invalid.event'), null);
		assert.equal(pubsub.getSubscribedTopic('com.invalid.event', topics), null);
	});

	it('should not validate descendant topics', function () {
		assert.equal(pubsub.getSubscribedTopic('com.test.event.descendant'), null);
		assert.equal(pubsub.getSubscribedTopic('com.test.topic.wildcard.descendant'), null);
		assert.equal(pubsub.getSubscribedTopic('com.test.wildcard.interior.descendant'), null);
		assert.equal(pubsub.getSubscribedTopic('com.test.event.descendant', topics), null);
		assert.equal(pubsub.getSubscribedTopic('com.test.topic.wildcard.descendant', topics), null);
		assert.equal(pubsub.getSubscribedTopic('com.test.wildcard.interior.descendant', topics), null);
	});
});
