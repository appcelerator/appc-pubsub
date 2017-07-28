'use strict';

var PubSub = require('../');

exports.createMockClient = function (config, sendCallback, receiveCallback) {
	config = config || {};
	let client = new PubSub(config);
	client._send = function () {
		sendCallback && sendCallback.apply(null, arguments);
	};
	return client;
};
