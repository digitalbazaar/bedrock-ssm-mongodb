/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _asymmetricKey = require('./asymmetric-key');
const _constants = require('./constants');
const _symmetricKey = require('./symmetric-key');
const assert = require('assert-plus');
const bedrock = require('bedrock');
const brPackageManager = require('bedrock-package-manager');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const {util: {BedrockError}} = bedrock;

// load config defaults
require('./config');

bedrock.events.on('bedrock.init', () => brPackageManager.register({
  alias: 'ssm-v1',
  packageName: 'bedrock-ssm-mongodb',
  type: 'bedrock-kms-store',
}));

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['ssm']);

  await promisify(database.createIndexes)([{
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
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} Key information.
 */
exports.generateKey = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {invocationTarget: {type}} = operation;
  assert.string(type, 'options.operation.type');

  if(_constants.KEY_TYPES.asymmetric.has(type)) {
    return _asymmetricKey.generateKeyPair({keyId, type});
  } else if(_constants.KEY_TYPES.symmetric.has(type)) {
    return _symmetricKey.generateKey({keyId, type});
  }

  throw new Error(`Unknown key type "${type}".`);
};

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{wrappedKey}`.
 */
exports.wrapKey = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key: kek} = await _getKeyRecord({id: keyId});
  return _symmetricKey.wrapKey({kek, operation});
};

/**
 * Unwraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{unwrappedKey}`.
 */
exports.unwrapKey = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key: kek} = await _getKeyRecord({id: keyId});
  return _symmetricKey.unwrapKey({kek, operation});
};

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{signatureValue}`.
 */
exports.sign = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});
  const {type} = key;

  if(_constants.KEY_TYPES.asymmetric.has(type)) {
    return _asymmetricKey.sign({key, operation});
  } else if(_constants.KEY_TYPES.symmetric.has(type)) {
    return _symmetricKey.sign({key, operation});
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
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{verified}`.
 */
exports.verify = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});
  const {type} = key;

  if(_constants.KEY_TYPES.symmetric.has(type)) {
    return _symmetricKey.verify({key, operation});
  } else if(_constants.KEY_TYPES.asymmetric.has(type)) {
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
 * @param {Object} options - The options to use.
 * @param {string} options.id - The ID of the key.
 *
 * @returns {Promise<Object>} The key record.
 */
async function _getKeyRecord({id}) {
  assert.string(id, 'options.id');

  const record = await database.collections.ssm.findOne(
    {id: database.hash(id)}, {_id: 0, key: 1, meta: 1});
  if(!record) {
    throw new BedrockError(
      'Key not found.',
      'NotFoundError',
      {key: id, httpStatusCode: 404, public: true});
  }

  return record;
}
