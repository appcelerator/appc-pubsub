'use strict';

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
 * @param {Object} body the request body
 * @param {Object} headers the request headers
 */
function Request(body, headers) {
	this.headers = headers || {};
	this.body = body || {};
}
exports.Request = Request;

/**
 * Mock response object to capture response details.
 */
function Response() {
}
exports.Response = Response;

Response.prototype.writeHead = function (code, headers) {
	this.code = code;
	this.headers = headers;
};
Response.prototype.write = function (str) {
	this.body = str;
};
Response.prototype.end = function () {
	this.ended = true;
};
Response.prototype.wasUnauthorized = function () {
	return this.code === 401 && this.ended;
};
