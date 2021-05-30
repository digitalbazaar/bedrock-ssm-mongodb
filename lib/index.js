/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _asymmetricKey = require('./asymmetric-key');
const _constants = require('./constants');
const _keyAgreementKey = require('./key-agreement-key');
const _symmetricKey = require('./symmetric-key');
const assert = require('assert-plus');
const bedrock = require('bedrock');
const brPackageManager = require('bedrock-package-manager');
const database = require('bedrock-mongodb');
const LRU = require('lru-cache');
const {util: {BedrockError}} = bedrock;

let KEY_RECORD_CACHE;

// load config defaults
require('./config');

bedrock.events.on('bedrock.init', async () => {
  const cfg = bedrock.config['ssm-mongodb'];
  KEY_RECORD_CACHE = new LRU({
    max: cfg.keyRecordCache.maxSize,
    maxAge: cfg.keyRecordCache.maxAge
  });
  return brPackageManager.register({
    alias: 'ssm-v1',
    packageName: 'bedrock-ssm-mongodb',
    type: 'webkms-module',
  });
});

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections(['ssm']);

  await database.createIndexes([{
    // cover queries by ID
    collection: 'ssm',
    fields: {id: 1},
    options: {unique: true, background: false}
  }]);
});

/**
 * @module bedrock-ssm-mongodb
 */

/**
 * Generates a new key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} Key information.
 */
exports.generateKey = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {invocationTarget: {type}} = operation;
  assert.string(type, 'options.operation.type');

  if(_constants.KEY_TYPES.asymmetric.has(type)) {
    return _asymmetricKey.generateKeyPair({keyId, type});
  }
  if(_constants.KEY_TYPES.keyAgreement.has(type)) {
    return _keyAgreementKey.generateKeyPair({keyId, type});
  }
  if(_constants.KEY_TYPES.symmetric.has(type)) {
    return _symmetricKey.generateKey({keyId, type});
  }

  throw new Error(`Unknown key type "${type}".`);
};

/**
 * Gets the key description (no private key material) for the given key.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 *
 * @returns {Promise<object>} Key information.
 */
exports.getKeyDescription = async ({keyId} = {}) => {
  const {key} = await _getKeyRecord({id: keyId});
  const description = {
    '@context': key['@context'],
    id: key.id,
    type: key.type
  };
  if(key.publicKeyMultibase) {
    description.publicKeyMultibase = key.publicKeyMultibase;
  }
  return description;
};

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object containing `{wrappedKey}`.
 */
exports.wrapKey = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key: kek} = await _getKeyRecord({id: keyId});
  const {type} = kek;

  if(_constants.KEY_TYPES.symmetric.has(type)) {
    return _symmetricKey.wrapKey({kek, operation});
  }
  if(_constants.KEY_TYPES.asymmetric.has(type)) {
    throw new Error(`Unsupported operation for key type "${type}".`);
  }
  if(_constants.KEY_TYPES.keyAgreement.has(type)) {
    throw new Error(`Unsupported operation for key type "${type}".`);
  }
  // this should never happen
  // this would mean that a key with an invalid type has been stored
  throw new Error(`Unknown key type "${type}".`);
};

/**
 * Unwraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object containing `{unwrappedKey}`.
 */
exports.unwrapKey = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key: kek} = await _getKeyRecord({id: keyId});
  const {type} = kek;

  if(_constants.KEY_TYPES.symmetric.has(type)) {
    return _symmetricKey.unwrapKey({kek, operation});
  }
  if(_constants.KEY_TYPES.asymmetric.has(type)) {
    throw new Error(`Unsupported operation for key type "${type}".`);
  }
  if(_constants.KEY_TYPES.keyAgreement.has(type)) {
    throw new Error(`Unsupported operation for key type "${type}".`);
  }
  // this should never happen
  // this would mean that a key with an invalid type has been stored
  throw new Error(`Unknown key type "${type}".`);
};

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object containing `{signatureValue}`.
 */
exports.sign = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});
  const {type} = key;

  if(_constants.KEY_TYPES.asymmetric.has(type)) {
    return _asymmetricKey.sign({key, operation});
  }
  if(_constants.KEY_TYPES.symmetric.has(type)) {
    return _symmetricKey.sign({key, operation});
  }
  if(_constants.KEY_TYPES.keyAgreement.has(type)) {
    throw new Error(`Unsupported operation for key type "${type}".`);
  }
  // this should never happen
  // this would mean that a key with an invalid type has been stored
  throw new Error(`Unknown key type "${type}".`);
};

/**
 * Verifies some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object containing `{verified}`.
 */
exports.verify = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});
  const {type} = key;

  if(_constants.KEY_TYPES.symmetric.has(type)) {
    return _symmetricKey.verify({key, operation});
  }
  if(_constants.KEY_TYPES.asymmetric.has(type)) {
    throw new Error(`Unsupported operation for key type "${type}".`);
  }
  if(_constants.KEY_TYPES.keyAgreement.has(type)) {
    throw new Error(`Unsupported operation for key type "${type}".`);
  }
  // this should never happen
  // this would mean that a key with an invalid type has been stored
  throw new Error(`Unknown key type "${type}".`);
};

/**
* Derives a shared secret via the given peer public key, typically for use
* as one parameter for computing a shared key. It should not be used as
* a shared key itself, but rather input into a key derivation function (KDF)
* to produce a shared key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object containing `{secret}`.
 */
exports.deriveSecret = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});
  const {type} = key;

  if(_constants.KEY_TYPES.keyAgreement.has(type)) {
    return _keyAgreementKey.deriveSecret({key, operation});
  }
  if(_constants.KEY_TYPES.asymmetric.has(type)) {
    throw new Error(`Unsupported operation for key type "${type}".`);
  }
  if(_constants.KEY_TYPES.symmetric.has(type)) {
    throw new Error(`Unsupported operation for key type "${type}".`);
  }
  // this should never happen
  // this would mean that a key with an invalid type has been stored
  throw new Error(`Unknown key type "${type}".`);
};

/**
 * Gets a previously stored key record.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.id - The ID of the key.
 *
 * @returns {Promise<object>} The key record.
 */
async function _getKeyRecord({id}) {
  assert.string(id, 'options.id');

  let promise = KEY_RECORD_CACHE.get(id);
  if(promise) {
    return promise;
  }

  promise = _getUncachedKeyRecord({id});
  KEY_RECORD_CACHE.set(id, promise);

  let record;
  try {
    record = await promise;
  } catch(e) {
    KEY_RECORD_CACHE.del(id);
    throw e;
  }

  return record;
}

async function _getUncachedKeyRecord({id}) {
  assert.string(id, 'options.id');

  const record = await database.collections.ssm.findOne(
    {id: database.hash(id)}, {projection: {_id: 0, key: 1, meta: 1}});
  if(!record) {
    throw new BedrockError(
      'Key not found.',
      'NotFoundError',
      {key: id, httpStatusCode: 404, public: true});
  }

  return record;
}
