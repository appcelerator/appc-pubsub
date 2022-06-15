# Appcelerator PubSub Client library

 [![NPM version](https://badge.fury.io/js/appc-pubsub.svg)](http://badge.fury.io/js/appc-pubsub)

The library makes it easy to publish events to the Appcelerator PubSub API service.

## Installation

    npm install appc-pubsub --save

## Usage

You must first include the library and create an instance.  At a minimum, you must pass in the `key` and `secret` values for constructing the client.

```javascript
const PubSubClient = require('appc-pubsub');
const pubsub = new PubSubClient({
  key: 'MY_KEY',
  secret: 'MY_SECRET'
});
```

Once you have created the client instance, you can publish events.

```javascript
pubsub.publish('com.foo.bar');
```

You can optional pass payload data for your event by passing an object as the second parameter:

```javascript
pubsub.publish('com.foo.bar', { bar: 1 });
```
## Events

### Configured
Emitted when the configurations (APIKey, secret..etc) are authenticated successfully by PubSub server.

```javascript
pubsub.on('configured', function (config) {
  //do something ...
});

//example of the returned config object: 
{
  can_publish: true,
  can_consume: false,
  events: {},
  auth_type: 'key_secret'
}
```

### Response
Emitted when an event is successfully sent.The `response` object that returned by the call-back contains a raw data of the event request (HTTP). i.e. `statusCode`,`body` etc... keys are available.

```javascript
pubsub.on('response', function (response) {
  //do something ...
});
```

### Event (WebHook)
*Note: Make sure the client has consumption enabled, check `can_consume` in the returned config object.*

Emitted when an event is received and that matches the subscribed topic.
Event's payload (object) will be returned by the call-back function

```javascript
const topicName = 'com.foo.downloaded'
pubsub.on(`event:${topicName}`, function (event) {
  // Log event name and data
  console.log(event.event);
  console.log(event.data);
  //do something with the event...
});
```

### Retry
Emitted when an event is rescheduled to re-sending. The event will be emitted first then the re-send occurs.

 *500ms Max time between event's emitting and re-sending*

```javascript
pubsub.on('retry', function (data) {
  //do something ...
});
```

### Unauthorized
Emitted when the client couldn't connect to the PubSub server due to bad credentials. i.e. HTTP code *401*

```javascript
pubsub.on('unauthorized', function (error) {
  //do something ...
});
```

### Logging

Logging is handled using the debug module with appc-pubsub:info and appc-pubsub:error namespaces. Logging can be enabled as part of the configuration options.

```javascript
const pubsub = new PubSubClient({
  key: 'MY_KEY',
  secret: 'MY_SECRET',
  debug: 'info', 'error' or true
});
```

## License

The library is Confidential and Proprietary to Appcelerator, Inc. and licensed under the Appcelerator Software License Agreement. Copyright (c) 2015 by Appcelerator, Inc. All Rights Reserved.
