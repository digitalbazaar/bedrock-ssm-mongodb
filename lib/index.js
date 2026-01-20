/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as _asymmetricKey from './core/asymmetricKey.js';
import * as _keyAgreementKey from './core/keyAgreementKey.js';
import * as _symmetricKey from './core/symmetricKey.js';
import * as bedrock from '@bedrock/core';
import * as brPackageManager from '@bedrock/package-manager';
import * as storage from './storage.js';
import assert from 'assert-plus';
import {Core} from './core/index.js';

// FIXME: remove
export const _helpers = {
  _symmetricKey,
  _asymmetricKey,
  _keyAgreementKey
};

// load config defaults
import './config.js';

// ensure any record wrapping keys get loaded
import './keySecrets.js';

let CORE;

bedrock.events.on('bedrock.init', async () => {
  CORE = new Core();

  return brPackageManager.register({
    alias: 'ssm-v1',
    packageName: '@bedrock/ssm-mongodb',
    type: 'webkms-module',
  });
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
  return storage.getKeyCount({keystoreId});
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

  return CORE.generateKey({keyId, controller, operation});
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
  const {key} = await storage.getKeyRecord({id: keyId});
  return CORE.getKeyDescription({key, controller});
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

  const {key} = await storage.getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});

  return CORE.wrapKey({key, operation});
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

  const {key} = await storage.getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});

  return CORE.unwrapKey({key, operation});
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

  const {key} = await storage.getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});

  return CORE.sign({key, operation});
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

  const {key} = await storage.getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});

  return CORE.verify({key, operation});
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

  const {key} = await storage.getKeyRecord({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});

  return CORE.deriveSecret({key, operation});
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
