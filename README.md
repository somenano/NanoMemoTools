nanomemotools.js
================

[![npm version](https://img.shields.io/npm/v/nanote.svg)](https://www.npmjs.com/package/nanomemotools)
![test workflow](https://github.com/somenano/NanoMemoTools/actions/workflows/test.yml/badge.svg)

Cryptographically secure memos for every Nano block

This library allows you to sign, verify signature, encrypt, and decrypt messages with the same keys used to sign a Nano block. It includes multiple modules to assist you in doing offline actions as well as communicating with the [NanoMemo.cc](https://nanomemo.cc) API endpoints. This documentation covers the capabilities of this library. For more details on the RESTful API on [NanoMemo.cc](https://nanomemo.cc) you can view the documentation here: [https://nanomemo.cc/docs/api](https://nanomemo.cc/docs/api).

Created by [SomeNano](https://somenano.com)
Twitter: [@SomeNanoTweets](https://twitter.com/SomeNanoTweets)

Installation
------------

Via NPM:

    $ npm install nanomemotools

also available as a standalone js file in the github repository/dist, [nanomemotools.js](https://github.com/somenano/nanomemotools)

```html
<script src="nanomemotools.js"></script>

<script>
  NanoMemoTools.memo...
</script>
```

Usage
-----

Full documentation is located in the [/docs](https://github.com/somenano/NanoMemoTools/tree/main/docs) directory or viewable online: (https://somenano.github.io/nanomemotools)

```javascript
const NanoMemoTools = require('nanomemotools');
```

Tests can be run with the command:

```
npm test
```

Example
-------

The [/test](https://github.com/somenano/NanoMemoTools/tree/main/test) directory on github has plenty of good examples.

## NanoMemoTools.memo

### Create a plaintext memo

```javascript
const NanoMemoTools = require('nanomemotools');
const hash = '4ABC34D...';
const message = 'test message';
const signing_address = 'nano_1abc...';
const memo = new NanoMemoTools.memo.Memo(
    hash,
    message,
    signing_address
);

// memo is unsigned at this point 
memo.valid_signature == false;

// Sign it with the private key of the Nano Account that owns the block with the provided hash
const signing_private_key = '234ABC...';
const signature = memo.sign(signing_private_key);
memo.valid_signature == true;
```

### Create an encrypted memo

```javascript
const NanoMemoTools = require('nanomemotools');
const hash = '4ABC34D...';
const encrypted_message = 'test message';
const signing_address = 'nano_1abc...';
const decrypting_address = 'nano_3fed...';
const memo = new NanoMemoTools.memo.EncryptedMemo(
    hash,
    encrypted_message,
    signing_address,
    decrypting_address
);

// memo is unsigned at this point 
memo.valid_signature == false;

// Sign it with the private key of the Nano Account that owns the block with the provided hash
const signing_private_key = '234ABC...';
const signature = memo.sign(signing_private_key);
memo.valid_signature == true;
```

### Convert plaintext memo to encrypted memo

```javascript
// Assume plaintext memo is already created...
const encrypted_memo = NanoMemoTools.memo.encrypt(memo, signing_private_key, decrypting_address);

// Signature is no longer valid since message was encrypted
encrypted_memo.valid_signature == false;

// Sign it with the private key of the Nano Account that owns the block with the provided hash
const signing_private_key = '234ABC...';
const signature = encrypted_memo.sign(signing_private_key);
encrypted_memo.valid_signature == true;
```

### Convert encrypted memo to plaintext memo

```javascript
// Assume encrypted memo is already created...
const memo = NanoMemoTools.memo.decrypt(encrypted_memo, decrypting_private_key);

// Signature is no longer valid since message was encrypted
memo.valid_signature == false;

// Sign it with the private key of the Nano Account that owns the block with the provided hash
const signing_private_key = '234ABC...';
const signature = memo.sign(signing_private_key);
memo.valid_signature == true;
```

## NanoMemoTools.server

### Get memo from server

```javascript
const NanoMemoTools = require('nanomemotools');
const hash = '4ABC34D...';
const memo = await NanoMemoTools.server.getMemo(hash);
```

### Save memo to server

Requires [api key](https://nanomemo.cc/api)

```javascript
const NanoMemoTools = require('nanomemotools');
const memo = new NanoMemoTools.memo.Memo( ... );
const api_key = '123...';
const api_secret = '321...';
const memo_response = await NanoMemoTools.server.saveMemo(memo, api_key, api_secret);
```

### Get user data

Requires [api key](https://nanomemo.cc/api)

```javascript
const NanoMemoTools = require('nanomemotools');
const api_key = '123...';
const api_secret = '321...';
const user_data = await NanoMemoTools.server.getUserData(api_key, api_secret);
```

### WebSocket

This websocket will send a message for every new memo that is created

```javascript
const NanoMemoTools = require('nanomemotools');
const websocket = NanoMemoTools.server.websocketSubscribe(function(msg) {
    // onmessage
    console.log(msg);
});

// Can also unsubscribe
NanoMemoTools.server.websocketUnsubscribe();
```

Considerations
--------------

If someone has access to your Nano seed or private key they can access and transfer funds from your Nano Account. This library never stores your seed or private key. This library never sends your seed or private key to any server. All digital signing and encryption or decryption actions that require a private key are self-contained in this library and its dependencies.

It is your responsibility to use this library in a responsible manner and manage your own seed or private key.

Additionally, this library is covered by an MIT License which means it is provided "as is", without warranty of any kind. We make every attempt to be transparent. Below you will find the dependencies this library uses with links to their code and documentation repositories for your review as you see fit.


Requirements
------------

* [nanocurrency](https://github.com/marvinroger/nanocurrency-js/)
* [tweetnacl-blake2b](https://github.com/dvdbng/tweetnacl-blake2b-js)
* [blakejs](https://github.com/dcposch/blakejs)
* Modified and locally included to use tweetnacl-blake2b instead of tweetnacl: [ed2curve](https://github.com/dchest/ed2curve-js)
* [axios](https://github.com/axios/axios)
* [reconnecting-websocket](https://github.com/pladaria/reconnecting-websocket)
* [ws](https://github.com/websockets/ws)