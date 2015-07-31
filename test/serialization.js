var should = require('should'),
	helper = require('./_helper');


describe('serialization', function () {

	it('should do no harm to original object', function (done) {
		var bar = {
			password: 'pass',
			password_salt: 'salt'
		},
		config = {
			key: 'key',
			secret: 'secret'
		},
		pubsub = helper.createMockClientWithSocketIO(config, function sender(name, event) {
			should(name).be.equal('event');
			should(event).be.an.object;
			should(event).have.property('data');
			should(event.data).have.property('password', '[HIDDEN]');
			should(event.data).have.property('password_salt', '[HIDDEN]');
			should(bar).have.property('password', 'pass');
			should(bar).have.property('password_salt', 'salt');
			pubsub.close();
			done();
		});
		pubsub.publish('foo', bar);
	});

});
