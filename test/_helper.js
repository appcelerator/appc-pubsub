'use strict';

var PubSub = require('../'),
	util = require('util'),
	EventEmitter = require('events').EventEmitter;

function MockSocketIO(sendCallback) {
	this.sendCallback = sendCallback;
}

util.inherits(MockSocketIO, EventEmitter);

MockSocketIO.prototype.close = function () {
	this._closed = true;
	this._shutdown = true;
	this._connected = false;
	this.emit('disconnect');
};

MockSocketIO.prototype.emit = function () {
	EventEmitter.prototype.emit.apply(this, arguments);
	this.sendCallback && this.sendCallback.apply(null, arguments);
};

exports.createMockClientWithSocketIO = function (config, sendCallback, receiveCallback) {
	config = config || {};
	config.preferWebSocket = true;
	let client = new PubSub(config);
	client._reconnect = function () {
		this._socket = new MockSocketIO(sendCallback, receiveCallback);
		this._authed = true;
		this._connecting = false;
		this._connected = true;
		this._shutdown = false;
		process.nextTick(this._runQueue.bind(this));
	};
	return client;
};
