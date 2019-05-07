# bedrock-ssm-mongodb

## Usage
This API is designed to be accessed using the
[bedrock-package-manager](https://github.com/digitalbazaar/bedrock-package-manager#usage)
API.

```js
const brPackageManager = require('bedrock-package-manager');

// require this module in the application
// it registers itself with bedrock-package-manager
require('bedrock-ssm-mongodb');

// use the API
exports.callMethod = async ({method, options, plugin}) => {
  // the alias for bedrock-ssm-mongodb is 'ssm-v1'
  // the type for bedrock-ssm-mongodb is 'web-kms-module'
  const {packageName} = brPackageManager.get(
    {alias: plugin, type: 'web-kms-module'});
  const store = require(packageName);

  const result = await store[method](options);

  return result;
};
```

## API Reference
<a name="module_bedrock-ssm-mongodb"></a>

## bedrock-ssm-mongodb

* [bedrock-ssm-mongodb](#module_bedrock-ssm-mongodb)
    * [.generateKey(options)](#module_bedrock-ssm-mongodb.generateKey) ⇒ <code>Promise.&lt;Object&gt;</code>
    * [.wrapKey(options)](#module_bedrock-ssm-mongodb.wrapKey) ⇒ <code>Promise.&lt;Object&gt;</code>
    * [.unwrapKey(options)](#module_bedrock-ssm-mongodb.unwrapKey) ⇒ <code>Promise.&lt;Object&gt;</code>
    * [.sign(options)](#module_bedrock-ssm-mongodb.sign) ⇒ <code>Promise.&lt;Object&gt;</code>
    * [.verify(options)](#module_bedrock-ssm-mongodb.verify) ⇒ <code>Promise.&lt;Object&gt;</code>

<a name="module_bedrock-ssm-mongodb.generateKey"></a>

### bedrock-ssm-mongodb.generateKey(options) ⇒ <code>Promise.&lt;Object&gt;</code>
Generates a new key.

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - Key information.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>Object</code> | The KMS operation. |

<a name="module_bedrock-ssm-mongodb.wrapKey"></a>

### bedrock-ssm-mongodb.wrapKey(options) ⇒ <code>Promise.&lt;Object&gt;</code>
Wraps a cryptographic key using a key encryption key (KEK).

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - An object containing `{wrappedKey}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>Object</code> | The KMS operation. |

<a name="module_bedrock-ssm-mongodb.unwrapKey"></a>

### bedrock-ssm-mongodb.unwrapKey(options) ⇒ <code>Promise.&lt;Object&gt;</code>
Unwraps a cryptographic key using a key encryption key (KEK).

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - An object containing `{unwrappedKey}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>Object</code> | The KMS operation. |

<a name="module_bedrock-ssm-mongodb.sign"></a>

### bedrock-ssm-mongodb.sign(options) ⇒ <code>Promise.&lt;Object&gt;</code>
Signs some data. Note that the data will be sent to the server, so if
this data is intended to be secret it should be hashed first. However,
hashing the data first may present interoperability issues so choose
wisely.

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - An object containing `{signatureValue}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>Object</code> | The KMS operation. |

<a name="module_bedrock-ssm-mongodb.verify"></a>

### bedrock-ssm-mongodb.verify(options) ⇒ <code>Promise.&lt;Object&gt;</code>
Verifies some data. Note that the data will be sent to the server, so if
this data is intended to be secret it should be hashed first. However,
hashing the data first may present interoperability issues so choose
wisely.

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - An object containing `{verified}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>Object</code> | The KMS operation. |
