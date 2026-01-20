/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as _asymmetricKey from './core/asymmetricKey.js';
import * as _keyAgreementKey from './core/keyAgreementKey.js';
import * as _symmetricKey from './core/symmetricKey.js';
import * as bedrock from '@bedrock/core';
import * as brPackageManager from '@bedrock/package-manager';
import * as database from '@bedrock/mongodb';
import {Core, splitKeyId} from './core/index.js';
import assert from 'assert-plus';
import {LRUCache as LRU} from 'lru-cache';

const {util: {BedrockError}} = bedrock;

export const _helpers = {
  _symmetricKey,
  _asymmetricKey,
  _keyAgreementKey
};

let KEY_RECORD_CACHE;

// load config defaults
import './config.js';

// ensure any record wrapping keys get loaded
import './keySecrets.js';

bedrock.events.on('bedrock.init', async () => {
  const cfg = bedrock.config['ssm-mongodb'];
  let cacheConfig = cfg.keyRecordCache;

  // coerce `maxSize` w/o `sizeCalculation` to `max`
  if(cacheConfig.maxSize !== undefined &&
    cacheConfig.sizeCalculation === undefined) {
    cacheConfig = {...cacheConfig, max: cacheConfig.maxSize};
    delete cacheConfig.maxSize;
  }

  // coerce `maxAge` to `ttl` in `cacheConfig`
  if(cacheConfig.maxAge !== undefined) {
    cacheConfig = {...cacheConfig, ttl: cacheConfig.maxAge};
    delete cacheConfig.maxAge;
  }

  KEY_RECORD_CACHE = new LRU(cacheConfig);

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
    options: {unique: true}
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

  const core = new Core();
  return core.generateKey({keyId, controller, operation});
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
  const core = new Core();
  return core.getKeyDescription({key, controller});
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

  const {key} = await _getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});

  const core = new Core();
  return core.wrapKey({key, operation});
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

  const {key} = await _getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});

  const core = new Core();
  return core.unwrapKey({key, operation});
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

  const core = new Core();
  return core.sign({key, operation});
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

  const core = new Core();
  return core.verify({key, operation});
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

  const core = new Core();
  return core.deriveSecret({key, operation});
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
    KEY_RECORD_CACHE.delete(id);
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
