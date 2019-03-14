/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const base64url = require('base64url-universal');
const bedrock = require('bedrock');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const uuid = require('uuid-random');
const {util: {BedrockError}} = bedrock;

// load config defaults
require('./config');

const AES_KW_ALGORITHM = 'id-aes256-wrap';
const AES_KW_RFC3394_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['ssm']);

  await promisify(database.createIndexes)([{
    // cover queries by ID
    collection: 'ssm',
    fields: {id: 1},
    options: {unique: true, background: false}
  }, {
    // cover queries by controller
    collection: 'ssm',
    fields: {controller: 1},
    options: {unique: false, background: false}
  }]);
});

/**
 * @module bedrock-ssm-mongodb
 */

/**
 * Generates a new key.
 *
 * @param {Object} options - The options to use.
 * @param {string} options.controller - The ID of the controller of the key.
 * @param {string} options.type - The type of key (e.g. 'AES-KW', 'HS256').
 *
 * @returns {Promise<Object>} An object containing `{id}`.
 */
exports.generateKey = async ({controller, type}) => {
  assert.string(controller, 'options.controller');
  assert.string(type, 'options.type');

  let key;
  const id = uuid();

  if(type === 'AES-KW') {
    // TODO: support other lengths?
    key = {
      algorithm: 'AES-KW',
      secret: base64url.encode(crypto.randomBytes(32))
    };
  } else if(type === 'HS256') {
    // TODO: support other hashes?
    key = {
      algorithm: 'HS256',
      secret: base64url.encode(crypto.randomBytes(32))
    };
  } else {
    throw new Error(`Unknown key type "${type}".`);
  }

  // insert the key and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  const record = {
    id: database.hash(id),
    controller: database.hash(controller),
    meta,
    key
  };
  try {
    await database.collections.ssm.insert(record, database.writeOptions);
    return {id};
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError(
      'Duplicate key identifier.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }
};

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {Object} options - The options to use.
 * @param {string} options.controller - The ID of the controller of the key.
 * @param {string} options.kekId - The ID of the KEK.
 * @param {string} options.key - The base64url-encoded cryptographic key.
 *
 * @returns {Promise<Object>} An object containing `{wrappedKey}`.
 */
exports.wrapKey = async ({controller, kekId, key}) => {
  assert.string(controller, 'options.controller');
  assert.string(kekId, 'options.kekId');
  assert.string(key, 'options.key');

  const {key: kek} = await _getKeyRecord({id: kekId, controller});
  if(kek.algorithm !== 'AES-KW') {
    throw new Error(`Unknown unwrapping algorithm "${kek.algorithm}".`);
  }

  const wrappedKey = await _aesWrapKey({kek, key});
  return {wrappedKey};
};

/**
 * Unwraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {Object} options - The options to use.
 * @param {string} options.controller - The ID of the controller of the key.
 * @param {string} options.kekId - The ID of the KEK.
 * @param {string} options.wrappedKey - The base64url-encoded cryptographic key.
 *
 * @returns {Promise<Object>} An object containing `{key}`.
 */
exports.unwrapKey = async ({controller, kekId, wrappedKey}) => {
  assert.string(controller, 'options.controller');
  assert.string(kekId, 'options.kekId');
  assert.string(wrappedKey, 'options.wrappedKey');

  const {key: kek} = await _getKeyRecord({id: kekId, controller});
  if(kek.algorithm !== 'AES-KW') {
    throw new Error(`Unknown unwrapping algorithm "${kek.algorithm}".`);
  }

  const key = await _aesUnwrapKey({kek, wrappedKey});
  return {key};
};

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {Object} options - The options to use.
 * @param {string} options.controller - The ID of the controller of the key.
 * @param {string} options.keyId - The ID of the signing key to use.
 * @param {Uint8Array|string} options.data - The data to sign as a Uint8Array
 *   or a base64url-encoded string.
 *
 * @returns {Promise<Object>} An object containing `{signature}`.
 */
exports.sign = async ({controller, keyId, data}) => {
  assert.string(controller, 'options.controller');
  assert.string(keyId, 'options.keyId');
  assert.string(data, 'options.data');

  const {key} = await _getKeyRecord({id: keyId, controller});

  const signature = await _hs256Sign({key, data});
  return {signature: base64url.encode(signature)};
};

/**
 * Verifies some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {Object} options - The options to use.
 * @param {string} options.controller - The ID of the controller of the key.
 * @param {string} options.keyId - The ID of the signing key to use.
 * @param {Uint8Array|string} options.data - The data to sign as a Uint8Array
 *   or a base64url-encoded string.
 * @param {string} options.signature - The base64url-encoded signature to
 *   verify.
 *
 * @returns {Promise<Object>} An object containing `{verified}`.
 */
exports.verify = async ({controller, keyId, data, signature}) => {
  assert.string(controller, 'options.controller');
  assert.string(keyId, 'options.keyId');
  assert.string(data, 'options.data');
  assert.string(signature, 'options.signature');

  const {key} = await _getKeyRecord({id: keyId, controller});

  const verified = await _hs256Verify({key, data, signature});
  return {verified};
};

/**
 * Gets a previously stored key record.
 *
 * @ignore
 * @param {Object} options - The options to use.
 * @param {string} options.controller - The controller of the key.
 * @param {string} options.id - The ID of the key.
 *
 * @returns {Promise<Object>} The key record.
 */
async function _getKeyRecord({controller, id}) {
  assert.string(controller, 'options.controller');
  assert.string(id, 'options.id');

  const record = await database.collections.ssm.findOne(
    {controller: database.hash(controller), id: database.hash(id)},
    {_id: 0, key: 1, meta: 1});
  if(!record) {
    throw new BedrockError(
      'Key not found.',
      'NotFoundError',
      {key: id, controller, httpStatusCode: 404, public: true});
  }

  return record;
}

async function _aesWrapKey({kek, key}) {
  key = base64url.decode(key);
  const secret = base64url.decode(kek.secret);
  const cipher = crypto.createCipheriv(
    AES_KW_ALGORITHM, secret, AES_KW_RFC3394_IV);
  const output = Buffer.concat([cipher.update(key), cipher.final()]);
  return base64url.encode(output);
}

async function _aesUnwrapKey({kek, wrappedKey}) {
  wrappedKey = base64url.decode(wrappedKey);
  const secret = base64url.decode(kek.secret);
  const decipher = crypto.createDecipheriv(
    AES_KW_ALGORITHM, secret, AES_KW_RFC3394_IV);
  const output = Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
  return base64url.encode(output);
}

async function _hs256Sign({key, data}) {
  const secret = base64url.decode(key.secret);
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(base64url.decode(data));
  return hmac.digest();
}

async function _hs256Verify({key, data, signature}) {
  signature = base64url.decode(signature);
  const signatureCheck = _hs256Sign({key, data});
  return crypto.timingSafeEqual(signature, signatureCheck);
}
