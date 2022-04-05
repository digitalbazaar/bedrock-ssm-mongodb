/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brPackageManager from '@bedrock/package-manager';
import * as database from '@bedrock/mongodb';
import * as _asymmetricKey from './asymmetric-key.js';
import * as _constants from './constants.js';
import * as _keyAgreementKey from './key-agreement-key.js';
import * as _symmetricKey from './symmetric-key.js';
import assert from 'assert-plus';
import LRU from 'lru-cache';
import urlTemplate from 'url-template';
import {splitKeyId} from './helpers.js';

const {util: {BedrockError}} = bedrock;

export const _helpers = {
  _symmetricKey,
  _asymmetricKey,
  _keyAgreementKey
};

let KEY_RECORD_CACHE;

// load config defaults
import './config.js';

bedrock.events.on('bedrock.init', async () => {
  const cfg = bedrock.config['ssm-mongodb'];
  KEY_RECORD_CACHE = new LRU({
    max: cfg.keyRecordCache.maxSize,
    maxAge: cfg.keyRecordCache.maxAge
  });
  return brPackageManager.register({
    alias: 'ssm-v1',
    packageName: '@bedrock/ssm-mongodb',
    type: 'webkms-module',
  });
});

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections(['ssm']);

  await database.createIndexes([{
    // cover queries by ID (<keystoreId>/<localId>)
    collection: 'ssm',
    fields: {keystoreId: 1, localId: 1},
    options: {unique: true, background: false}
  }]);
});

/**
 * @module bedrock-ssm-mongodb
 */

/**
 * Gets the number of keys in a given keystore.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keystoreId - The ID of the keystore.
 *
 * @returns {Promise<object>} Key count information.
 */
export async function getKeyCount({keystoreId} = {}) {
  const count = await database.collections.ssm.countDocuments({keystoreId});
  return {count};
}

/**
 * Generates a new key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.controller - The key controller.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} Key information.
 */
export async function generateKey({keyId, controller, operation}) {
  assert.string(keyId, 'options.keyId');
  assert.string(controller, 'options.controller');
  assert.object(operation, 'options.operation');

  const {
    invocationTarget: {
      type, maxCapabilityChainLength, publicAlias, publicAliasTemplate
    }
  } = operation;
  assert.string(type, 'options.operation.invocationTarget.type');
  assert.optionalNumber(
    maxCapabilityChainLength,
    'options.operation.invocationTarget.maxCapabilityChainLength');
  assert.optionalString(
    publicAlias, 'options.operation.invocationTarget.publicAlias');
  assert.optionalString(
    publicAliasTemplate,
    'options.operation.invocationTarget.publicAliasTemplate');

  if(publicAlias && publicAliasTemplate) {
    throw new Error(
      'Only one of "publicAlias" or "publicAliasTemplate" may be given.');
  }

  if(_constants.KEY_TYPES.asymmetric.has(type)) {
    return _asymmetricKey.generateKeyPair({
      keyId, type, controller,
      maxCapabilityChainLength, publicAlias, publicAliasTemplate
    });
  }
  if(_constants.KEY_TYPES.keyAgreement.has(type)) {
    return _keyAgreementKey.generateKeyPair({
      keyId, type, controller,
      maxCapabilityChainLength, publicAlias, publicAliasTemplate
    });
  }
  if(_constants.KEY_TYPES.symmetric.has(type)) {
    if(publicAlias || publicAliasTemplate) {
      throw new Error(
        'Neither "publicAlias" nor "publicAliasTemplate" are supported by ' +
        `key type ${type}.`);
    }
    return _symmetricKey.generateKey({
      keyId, type, controller, maxCapabilityChainLength
    });
  }

  throw new Error(`Unknown key type "${type}".`);
}

/**
 * Gets the key description (no private key material) for the given key.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.controller - The key controller.
 *
 * @returns {Promise<object>} Key information.
 */
export async function getKeyDescription({keyId, controller} = {}) {
  const {key} = await _getKeyRecord({id: keyId});
  const description = {
    '@context': key['@context'],
    id: key.id,
    type: key.type,
    controller
  };
  if(key.publicKeyMultibase) {
    description.publicKeyMultibase = key.publicKeyMultibase;
  }

  // override `id` with `publicAlias` / `publicAliasTemplate` if available
  if(key.publicAlias) {
    description.id = key.publicAlias;
  } else if(key.publicAliasTemplate) {
    // compute public alias from template
    const template = urlTemplate.parse(key.publicAliasTemplate);
    description.id = template.expand(description);
  }

  return description;
}

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{wrappedKey}`.
 */
export async function wrapKey({keyId, operation, zcapInvocation}) {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key: kek} = await _getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key: kek, zcapInvocation});
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
}

/**
 * Unwraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{unwrappedKey}`.
 */
export async function unwrapKey({keyId, operation, zcapInvocation}) {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key: kek} = await _getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key: kek, zcapInvocation});
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
}

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{signatureValue}`.
 */
export async function sign({keyId, operation, zcapInvocation}) {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});
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
}

/**
 * Verifies some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{verified}`.
 */
export async function verify({keyId, operation, zcapInvocation}) {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});
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
}

/**
* Derives a shared secret via the given peer public key, typically for use
* as one parameter for computing a shared key. It should not be used as
* a shared key itself, but rather input into a key derivation function (KDF)
* to produce a shared key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{secret}`.
 */
export async function deriveSecret({keyId, operation, zcapInvocation}) {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});
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
}

function _checkZcapInvocationRules({key, zcapInvocation}) {
  // operation not invoked via zcap
  if(!zcapInvocation) {
    return;
  }
  // no extra zcap invocation restrictions on the key
  if(key.maxCapabilityChainLength === undefined) {
    return;
  }
  // ensure zcap invocation capability change length does not exceed the
  // rules from the key record
  if(zcapInvocation.dereferencedChain.length > key.maxCapabilityChainLength) {
    throw new Error(
      'Maximum zcap invocation capability chain length ' +
      `(${key.maxCapabilityChainLength}) exceeded.`);
  }
}

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
  const {keystoreId, localId} = splitKeyId({id});
  const record = await database.collections.ssm.findOne(
    {keystoreId, localId}, {projection: {_id: 0, key: 1, meta: 1}});
  if(!record) {
    throw new BedrockError(
      'Key not found.',
      'NotFoundError',
      {key: id, httpStatusCode: 404, public: true});
  }

  return record;
}
