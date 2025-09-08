'use strict';
const EventEmitter = require('events');

const PubSub = require('../');

/**
 * Mock client for avoiding config fetch
 * @class
 */
class MockConfigClient extends PubSub {
	constructor(opts) {
		super(opts);

		this._config = opts.config;
	}

	async _fetchConfig() {
		// do nothing
	}
}

class MockSendCallbackClient extends MockConfigClient {
	#sendCallback;

	constructor(opts, sendCallback) {
		super(opts);

		this.#sendCallback = sendCallback;
	}

	async _send(id, data) {
		this.#sendCallback && this.#sendCallback.call(null, data);
	}
}

/**
 * Mock request object
 */
class MockRequest extends EventEmitter {
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

/**
 * Mock response object to capture response details.
 */
class MockResponse {
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

module.exports = {
	MockConfigClient,
	MockSendCallbackClient,
	MockRequest,
	MockResponse
};
