'use strict';
const EventEmitter = require('events');

const util = require('util');
const PubSub = require('../');

exports.createMockClient = function (config, sendCallback) {
	config = config || {};
	let client = new PubSub(config);
	client._send = function (_id, data) {
		sendCallback && sendCallback.call(null, data);
	};
	return client;
};

/**
 * Mock client for avoiding config fetch
 * @class
 */
function MockConfigClient() {
	return PubSub.apply(this, arguments);
}
util.inherits(MockConfigClient, PubSub);
MockConfigClient.prototype.fetchConfig = () => null;

/**
 * Create a client that can have the client config set instead of fetched.
 * @param {Object} config the config object
 * @return {MockConfigClient} client
 */
exports.createMockConfigClient = function (config) {
	return new MockConfigClient(config);
};

/**
 * Mock request object
 */
class Request extends EventEmitter {
	/**
	 * @param {Object} body the request body
	 * @param {Object} headers the request headers
	 */
	constructor (body, headers) {
		super();
		this.headers = headers || {};
		this.body = body;
	}
}
exports.Request = Request;

/**
 * Mock response object to capture response details.
 */
class Response {
	writeHead(code, headers) {
		this.code = code;
		this.headers = headers;
	}
	write(str) {
		this.body = str;
	}
	end() {
		this.ended = true;
	}
	wasUnauthorized() {
		return this.code === 401 && this.ended;
	}
}
exports.Response = Response;
