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

Once you have created the client instance, you can publish events.

```javascript
pubsub.publish('com.foo.bar');
```

You can optional pass payload data for your event by passing an object as the second parameter:

```javascript
pubsub.publish('com.foo.bar', {bar:1});
```
## Events

### Configured
Emitted when the configurations (APIKey, secret..etc) are authenticated successfully by PubSub server.

```javascript
pubsub.on('configured', function(error){
    //do something ...
});
```
 
### Unauthorized
Emitted when the client couldn't connect to the PubSub server due to bad credentials. i.e. HTTP code *401*

```javascript
pubsub.on('unauthorized', function(error){
    //do something ...
});
```
The call-back function will be called 

## License

The library is Confidential and Proprietary to Appcelerator, Inc. and licensed under the Appcelerator Software License Agreement. Copyright (c) 2015 by Appcelerator, Inc. All Rights Reserved.
