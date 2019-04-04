# Appcelerator PubSub Client library

 [![NPM version](https://badge.fury.io/js/appc-pubsub.svg)](http://badge.fury.io/js/appc-pubsub)

The library makes it easy to publish events to the Appcelerator PubSub API service.

## Installation

    npm install appc-pubsub --save

## Usage

You must first include the library and create an instance.  At a minimum, you must pass in the `key` and `secret` values for constructing the client.

```javascript
var PubSub = require('appc-pubsub'),
    pubsub = new PubSub({
        key: 'MY_KEY',
        secret: 'MY_SECRET'
    });
```
### Options
------
The PubSub constructor takes an object that may contain any of the following keys:

#### batching
------
Determines if the events should be send in batch. Defaults to false.

When set to true (or an object of options) events will be staged and sent on a recurring interval determined by the option **maxWait** in milliseconds.

## Example
---

```javascript
pubsub.publish('com.foo.bar');
```

You can optional pass payload data for your event by passing an object as the second parameter:

```javascript
pubsub.publish('com.foo.bar', {bar:1});
```

## License

The library is Confidential and Proprietary to Appcelerator, Inc. and licensed under the Appcelerator Software License Agreement. Copyright (c) 2015 by Appcelerator, Inc. All Rights Reserved.
