# bedrock-ssm-mongodb

# API Reference
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
**Returns**: <code>Promise.&lt;Object&gt;</code> - An object containing `{id}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | The options to use. |
| options.controller | <code>string</code> | The ID of the controller of the key. |
| options.type | <code>string</code> | The type of key (e.g. 'AES-KW', 'HS256'). |

<a name="module_bedrock-ssm-mongodb.wrapKey"></a>

### bedrock-ssm-mongodb.wrapKey(options) ⇒ <code>Promise.&lt;Object&gt;</code>
Wraps a cryptographic key using a key encryption key (KEK).

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - An object containing `{wrappedKey}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | The options to use. |
| options.controller | <code>string</code> | The ID of the controller of the key. |
| options.kekId | <code>string</code> | The ID of the KEK. |
| options.key | <code>string</code> | The base64url-encoded cryptographic key. |

<a name="module_bedrock-ssm-mongodb.unwrapKey"></a>

### bedrock-ssm-mongodb.unwrapKey(options) ⇒ <code>Promise.&lt;Object&gt;</code>
Unwraps a cryptographic key using a key encryption key (KEK).

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - An object containing `{key}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | The options to use. |
| options.controller | <code>string</code> | The ID of the controller of the key. |
| options.kekId | <code>string</code> | The ID of the KEK. |
| options.wrappedKey | <code>string</code> | The base64url-encoded cryptographic key. |

<a name="module_bedrock-ssm-mongodb.sign"></a>

### bedrock-ssm-mongodb.sign(options) ⇒ <code>Promise.&lt;Object&gt;</code>
Signs some data. Note that the data will be sent to the server, so if
this data is intended to be secret it should be hashed first. However,
hashing the data first may present interoperability issues so choose
wisely.

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;Object&gt;</code> - An object containing `{signature}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | The options to use. |
| options.controller | <code>string</code> | The ID of the controller of the key. |
| options.keyId | <code>string</code> | The ID of the signing key to use. |
| options.data | <code>Uint8Array</code> \| <code>string</code> | The data to sign as a Uint8Array   or a base64url-encoded string. |

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
| options.controller | <code>string</code> | The ID of the controller of the key. |
| options.keyId | <code>string</code> | The ID of the signing key to use. |
| options.data | <code>Uint8Array</code> \| <code>string</code> | The data to sign as a Uint8Array   or a base64url-encoded string. |
| options.signature | <code>string</code> | The base64url-encoded signature to   verify. |

