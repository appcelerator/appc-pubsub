'use strict';

const should = require('should');
const helper = require('./_helper');

describe('sanitization', function () {

	it('should do no harm to original object', function (done) {
		let bar = {
				password: 'pass',
				password_salt: 'salt'
			},
			config = {
				key: 'key',
				secret: 'secret'
			},
			pubsub = helper.createMockClient(config, function sender(event) {
				should(event.event).be.equal('foo');
				should(event).have.property('data');
				should(event.data).have.property('password', '[HIDDEN]');
				should(event.data).have.property('password_salt', '[HIDDEN]');
				should(bar).have.property('password', 'pass');
				should(bar).have.property('password_salt', 'salt');
				done();
			});
		pubsub.publish('foo', bar);
	});

});
